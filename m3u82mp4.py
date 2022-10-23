# -*- coding:utf-8 -*-


import argparse
import os
import platform
import re
import shutil
import time
from datetime import datetime
from urllib.parse import urljoin
import gevent
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all()
import requests
import urllib3

from os import environ
environ['LOGURU_FORMAT'] = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:<5}</level> | <level>{message}</level>"
from loguru import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class M3u8VideoDownloader:
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
    }

    def __init__(self, m3u8_url, download_path=None, video_name=None, is_del_clip=True, test_download_num=0,
                 retry_count=10, thread_num=30, dec_func=None, m3u8_content_plaintext=None):
        """
        :param m3u8_url: m3u8链接
        :param download_path: 下载路径
        :param video_name: 视频名称（不能出现括号）
        :param is_del_clip: 合并视频完成后是否删除原片段
        :param test_download_num: 测试下载视频数量
        :param retry_count: 单个视频片段下载失败重试次数
        :param thread_num: 下载线程数
        :param dec_func: m3u8内容解密函数（内容被加密时可传入解密函数，或直接将解密后的明文内容传递给参数m3u8_content_plaintext）
        :param m3u8_content_plaintext: 已解密的m3u8明文内容
        """
        self.m3u8_url = m3u8_url
        self.download_path = download_path
        self.cache_path = None         # 临时缓存路径
        self.video_name = video_name or str(int(time.time()))
        self.video_name_suffix = '.mp4'  # 文件类型后缀
        self.is_del_clip = is_del_clip
        self.test_download_num = test_download_num
        self.retry_count = retry_count
        self.thread_num = min(thread_num, 50)
        self.max_merge_num = 500       # 单次合并文件最大数量
        self.dec_func = dec_func
        self.m3u8_content_plaintext = m3u8_content_plaintext
        self.key_url = None
        self.key = None
        self.iv = None
        self.decipher = None
        self.video_clip_list = []      # 视频片段名称列表
        self.total_duration = 0        # 视频总时间（分钟）
        self.total_video_clip_num = 0  # 视频片段数量
        self.download_num = 0          # 已下载数量
        self.total_download_size = 0   # 总下载大小
        self.is_special_link = False   # 视频片段链接未带后缀（例`.ts`）时为True，一般出现在m3u8内容被加密的视频网站

    def fetch(self, url, binary=False):
        resp = requests.get(url, headers=self.headers, timeout=30, verify=False)
        status_code = resp.status_code
        if status_code != 200:
            raise Exception(f'请求失败({status_code}):{url}')
        if binary:
            return resp.content
        return resp.content.decode()

    def get_m3u8_content(self):
        """获取m3u8内容"""
        logger.info(f'M3U8链接：{self.m3u8_url}')
        try:
            m3u8_content = self.fetch(self.m3u8_url)
        except Exception as e:
            raise Exception(f'获取m3u8内容失败({self.m3u8_url})：{repr(e)}')

        # 如果内容被加密，需要通过传入的解密函数进行解密
        if self.dec_func:
            try:
                m3u8_content = self.dec_func(m3u8_content)
            except Exception as e:
                raise Exception(f'解密m3u8内容失败({self.m3u8_url})：{repr(e)}')

        if '#EXTM3U' not in m3u8_content:
            raise Exception(f'错误的M3U8信息，请确认链接是否正确：{self.m3u8_url}<{m3u8_content}>')
        if '#EXT-X-STREAM-INF' in m3u8_content:
            m3u8_url_list = [line for line in m3u8_content.split('\n') if line.find('.m3u8') != -1]
            if len(m3u8_url_list) > 1:
                logger.info(f'发现{len(m3u8_url_list)}个m3u8地址：{m3u8_url_list}')
            self.m3u8_url = urljoin(self.m3u8_url, m3u8_url_list[0])
            return self.get_m3u8_content()
        # logger.info(f'M3U8内容已获取完成：{self.m3u8_url}')
        return m3u8_content

    def parse_m3u8_info(self, m3u8_content):
        """解析m3u8文件：获取解密key、iv、视频url列表"""
        all_lines = m3u8_content.strip('\n').split('\n')
        is_updated_base_url = False
        is_exist_clip = False
        offset = 0

        for index, line in enumerate(all_lines):
            if '#EXT-X-KEY' in line:
                # 避免重复解析key与iv
                if not (self.key_url and self.iv):
                    method, key_url_part, self.iv = self.parse_ext_x_key(line)
                    self.key_url = urljoin(self.m3u8_url, key_url_part)
                    logger.info(f'视频已加密：{method}  Key地址:{key_url_part}')
            elif '#EXTINF' in line:
                for i in range(5):
                    _index = index + i + 1
                    # 过滤标签
                    if not all_lines[_index].startswith('#'):
                        next_line = all_lines[_index].rstrip()
                        break
                else:
                    raise Exception('未发现有效的下载链接')
                if not is_updated_base_url:
                    is_exist_clip = True
                    is_updated_base_url = True
                    if next_line.startswith('http') or next_line.startswith('/'):
                        suffix = next_line.rsplit('/', 1)[-1]
                        if '.ts' in suffix or '.' in suffix:
                            # 将下载地址更新到m3u8_url
                            self.m3u8_url = urljoin(self.m3u8_url, next_line)
                        else:
                            if len(next_line.split('//')[-1].split('/')) <= 2:
                                offset = 1
                            self.m3u8_url = next_line[:next_line.rfind('/', 0, next_line.rfind('/') + offset) + 1]
                            self.is_special_link = True
                        logger.debug(f'视频下载主地址已更新：{self.m3u8_url.rsplit("/", 1)[0]}')
                # 计算视频总时长
                duration_str = line.split(':')[-1].rstrip()
                try:
                    self.total_duration += float(duration_str[:-1])
                except ValueError:
                    pass
                # 添加视频到视频片段名称列表
                if self.is_special_link:
                    clip_name = next_line[next_line.rfind('/', 0, next_line.rfind('/') + offset) + 1:].replace('/', '@@')
                    clip_name = '.ts?'.join(clip_name.split('?')) if '?' in clip_name else clip_name + '.ts'
                    self.video_clip_list.append(clip_name)
                else:
                    clip_name = next_line.rsplit('/', 1)[-1]
                    self.video_clip_list.append(clip_name)
        if not is_exist_clip:
            raise Exception('未发现视频下载链接')
        self.total_duration = int(self.total_duration) // 60 + 1
        self.total_video_clip_num = len(self.video_clip_list)
        logger.info(f'M3U8内容解析已完成，视频片段数量：{self.total_video_clip_num}，视频时长：{self.total_duration}分钟，下载主地址：{self.m3u8_url.rsplit("/", 1)[0]}')

    @staticmethod
    def parse_ext_x_key(ext_x_key: str) -> (str, str, bytes):
        """解析#EXT-X-KEY中的key链接与iv"""
        ret = re.search(r'METHOD=(.*?),URI="(.*?)"(?:,IV=(\w+))?', ext_x_key)
        method, key_url, iv = ret.groups()
        iv = iv.replace('0x', '')[:16].encode() if iv else b''
        return method, key_url, iv

    def get_key(self):
        try:
            self.key = self.fetch(self.key_url, binary=True)
        except Exception as e:
            raise Exception(f'获取key失败({self.key_url})：{repr(e)}')
        logger.info(f'key解析已完成：{self.key}  iv:{self.iv or "无"}')

    def init_decipher(self):
        self.decipher = AES.new(self.key, AES.MODE_CBC, self.iv or self.key[:16])

    def download_all_videos(self):
        # 重试时重新初始化已下载数量
        if self.cache_path:
            self.download_num = 0
        else:
            # 默认保存在用户目录下的Downloads/videos文件夹内
            if self.download_path is None:
                self.download_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            self.download_path = os.path.join(self.download_path, 'Videos')
        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path)
        file_list = os.listdir(self.download_path)
        if f'{self.video_name}{self.video_name_suffix}' in file_list or f'{self.video_name}.ts' in file_list:
            logger.info(f'视频已经存在：{self.video_name}')
            return
        logger.info(f'视频保存目录：{self.download_path}')
        # 临时缓存目录
        if not self.cache_path:
            self.cache_path = os.path.join(self.download_path, datetime.now().strftime('%Y%m%d'))
        if not os.path.exists(self.cache_path):
            os.makedirs(self.cache_path)

        # 测试下载部分视频
        if self.test_download_num > 0:
            self.video_clip_list = self.video_clip_list[:self.test_download_num]
            logger.info(f'当前为测试模式，设置下载视频片段数量：{self.test_download_num}')

        logger.info(f'即将开始下载视频：{self.video_name}{self.video_name_suffix}')
        start_time = int(time.time())

        # 协程池
        pool = Pool(self.thread_num)
        for clip in self.video_clip_list:
            pool.add(gevent.spawn(self.download_decode_save_video, clip))
        pool.join()

        # 线程池
        # from concurrent.futures.thread import ThreadPoolExecutor
        # with ThreadPoolExecutor(max_workers=self.thread_num) as pool:
        #     pool.map(self.download_decode_save_video, self.video_clip_list)

        spend_time = int(time.time()) - start_time
        logger.info(f'下载视频耗时：{spend_time}秒')

    def download_decode_save_video(self, clip):
        """下载、解码、保存视频"""
        url = urljoin(self.m3u8_url, clip)
        # 删除文件名中的参数部分，但url中的参数不能少
        clip = clip.split('?')[0]
        full_path_filename = os.path.join(self.cache_path, clip)
        if os.path.exists(full_path_filename):
            self.download_num += 1
            logger.debug(f'视频片段已存在({self.download_num})：{clip}')
            return

        if self.is_special_link:
            url = url.replace('@@', '/').replace('.ts', '')

        # 下载单个视频
        raw_data = self.download_single_video(url)
        # 解码视频
        data = self.decode_video_clip(clip, raw_data)
        # 保存视频
        self.save_video_clip(clip, full_path_filename, data)

    def download_single_video(self, url):
        status_code = 0
        for i in range(self.retry_count):
            try:
                response = requests.get(url, headers=self.headers, timeout=30, verify=False)
            except Exception as e:
                if i == self.retry_count - 1:
                    raise Exception(f'下载失败({url})：{repr(e)}')
            else:
                status_code = response.status_code
                if status_code == 200:
                    data = response.content
                    break
                time.sleep(0.3)
        else:
            raise Exception(f'多次尝试下载失败({url})：{status_code}')
        return data

    def decode_video_clip(self, clip, data):
        if self.decipher is not None:
            try:
                data = self.decipher.decrypt(data)
            except Exception as e:
                raise Exception(f'数据解密失败({clip})：{repr(e)}<{len(data)}>')
        return data

    def save_video_clip(self, filename, full_path_filename, data):
        with open(full_path_filename, 'wb') as f:
            f.write(data)
        file_size = len(data)
        self.total_download_size += file_size
        self.download_num += 1
        file_size_m = round(file_size / float(1024*1024), 2)
        total_download_size_m = round(self.total_download_size/float(1024*1024), 2)
        total_num = self.test_download_num if 0 < self.test_download_num < self.total_video_clip_num else self.total_video_clip_num
        remainder = total_num - self.download_num
        logger.debug(f'已完成({self.download_num})-剩余({remainder})：{filename} <{file_size_m:0<4}M - {total_download_size_m}M>')

    def win_merge(self):
        """Windows平台合并视频"""
        cur_path = os.getcwd()
        os.chdir(self.cache_path)
        merge_num = 1
        merge_video_list = []
        start_index, end_index = 0, self.max_merge_num
        while 1:
            cur_merge_list = [clip.split('?')[0] for clip in self.video_clip_list[start_index:end_index]]
            if not cur_merge_list:
                video_filename = f'{self.video_name}{self.video_name_suffix}'
                if not merge_video_list:
                    logger.error('视频合并失败')
                    os.chdir(cur_path)
                    return False
                elif len(merge_video_list) == 1:
                    os.rename(merge_video_list[0], video_filename)
                    if self.is_del_clip:
                        os.system('del /Q *.ts*')
                    if self.is_special_link:
                        os.rename(video_filename, video_filename.replace(self.video_name_suffix, '.ts'))
                    os.chdir(cur_path)
                    video_filename = self.move_del_file(video_filename)
                    logger.info(f'视频合并已全部完成：{video_filename}')
                else:
                    status = os.system(f"copy /b {'+'.join(merge_video_list)} {video_filename} >> merge.log")
                    if status == 0:
                        if self.is_del_clip:
                            os.system('del /Q *.ts*')
                        if self.is_special_link:
                            os.rename(video_filename, video_filename.replace(self.video_name_suffix, '.ts'))
                        os.chdir(cur_path)
                        video_filename = self.move_del_file(video_filename)
                        logger.info(f'视频合并已全部完成：{video_filename}')
                    else:
                        os.chdir(cur_path)
                        logger.error(f'最后一次合并失败：{merge_video_list}')
                return True
            cur_video_name = f'{self.video_name}_temp{merge_num}.ts'
            cmd_name = '+'.join(cur_merge_list)
            status = os.system(f"copy /b {cmd_name} {cur_video_name} >> merge.log")
            if status == 0:
                merge_num += 1
                start_index, end_index = end_index, end_index + self.max_merge_num
                merge_video_list.append(cur_video_name)
                logger.info(f'本次合并{len(cur_merge_list)}个视频完成：{cur_video_name}')
            else:
                logger.error('视频合并失败')
                os.chdir(cur_path)
                return False

    def linux_merge(self):
        """Linux或MacOS平台合并视频（需要使用ffmpeg）"""
        video_file_list = [os.path.join(self.cache_path, filename.split('?')[0]) for filename in self.video_clip_list]
        # 将video路径并合成一个字符参数
        file_argv = '|'.join(video_file_list)
        # 指定输出文件名称
        mp4_filename = os.path.join(self.cache_path, f'{self.video_name}{self.video_name_suffix}')
        # 调取系统命令使用ffmpeg将ts合成mp4文件
        cmd = f'ffmpeg -i "concat:{file_argv}" -c copy {mp4_filename}'
        status = os.system(cmd)
        if status == 0:
            # 删除原ts文件
            if self.is_del_clip:
                os.system(f'rm {os.path.join(self.cache_path, "*.ts*")}')
            if self.is_special_link:
                os.rename(mp4_filename, mp4_filename.replace(self.video_name_suffix, '.ts'))
            mp4_filename = self.move_del_file(mp4_filename)
            logger.info(f'视频已全部合并完成：{mp4_filename}')
            return True
        else:
            logger.error('视频合并失败')
            return False

    def move_del_file(self, video_filename):
        """移动文件并删除临时文件夹"""
        if self.is_special_link:
            video_filename = video_filename.replace(self.video_name_suffix, '.ts')
        shutil.move(os.path.join(self.cache_path, video_filename), self.cache_path.rsplit(os.sep, 1)[0])
        shutil.rmtree(self.cache_path)
        return video_filename

    def merge_video_file(self):
        """合并视频片段"""
        if self.test_download_num == 0:
            total_video_clip_num = self.total_video_clip_num
        else:
            if self.test_download_num < self.total_video_clip_num:
                total_video_clip_num = self.test_download_num
            else:
                total_video_clip_num = self.total_video_clip_num

        if self.download_num != total_video_clip_num:
            logger.error(f'视频信息不完整，取消合并：{self.download_num}-{total_video_clip_num}')
            return False
        logger.info(f'视频已全部下载完成，即将合并{self.download_num}个视频...')

        # 根据系统选择相应的合并方式
        sys_info = platform.system()
        if 'Windows' in sys_info:   # Windows
            status = self.win_merge()
        elif 'Linux' in sys_info:   # Linux
            status = self.linux_merge()
        elif 'Darwin' in sys_info:  # MacOS
            status = self.linux_merge()
        else:
            raise Exception(f'其它系统信息：{sys_info}')
        return status

    def start(self):
        # 1.获取m3u8内容
        m3u8_content = self.m3u8_content_plaintext or self.get_m3u8_content()

        # 2.解析m3u8内容
        self.parse_m3u8_info(m3u8_content)

        if not self.video_clip_list:
            logger.error('解析未发现有效的视频片段')
            return

        # 3.如果存在加密，获取解密key，并初始化解密器
        if self.key_url:
            self.get_key()
            self.init_decipher()

        # 下载/合并失败或视频片段不完整时重试3次
        for _ in range(3):
            # 4.下载视频
            self.download_all_videos()
            if self.download_num == 0:
                return

            # 5.合并视频
            if self.merge_video_file():
                break


def parse_args():
    arg_parser = argparse.ArgumentParser(description='========== M3U8下载器 ==========')
    arg_parser.add_argument('url', help='m3u8地址')
    arg_parser.add_argument('-p', '--path', help='下载路径')
    arg_parser.add_argument('-n', '--name', help='视频名称')
    arg_parser.add_argument('-c', '--count', type=int, help='测试下载视频片段数量', default=0)
    args = arg_parser.parse_args()
    return args.url, args.path, args.name, args.count


def download(m3u8_url, download_path=None, custom_video_name=None, test_download_num=0, m3u8_content=None):
    """
    :param m3u8_url: m3u8链接
    :param download_path: 下载路径
    :param custom_video_name: 自定义视频名称
    :param test_download_num: 测试下载数量（为0时下载全部）
    :param m3u8_content: m3u8明文内容
    :return:
    """
    if not (m3u8_url and m3u8_url.startswith('http')):
        logger.error(f'url不正确：{m3u8_url}')
        return

    if '.mp4' in m3u8_url:
        logger.error(f'当前为mp4链接(暂不支持下载)：{m3u8_url}')
        return

    # 下载视频
    downloader = M3u8VideoDownloader(m3u8_url=m3u8_url,
                                     download_path=download_path,
                                     video_name=custom_video_name,
                                     test_download_num=test_download_num,
                                     m3u8_content_plaintext=m3u8_content)
    try:
        downloader.start()
    except Exception as e:
        logger.exception(f'视频下载失败({repr(e)})：{m3u8_url}')


if __name__ == '__main__':

    m3u8_url = input('please input your m3u8 link here:')

    # 以下3项为可选参数
    download_path = ''
    video_title = None
    test_num = 0

    if not m3u8_url:
        m3u8_url, download_path, video_title, test_num = parse_args()

    download(m3u8_url, download_path, video_title, test_num)