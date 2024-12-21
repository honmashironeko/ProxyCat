import os
import logging
from typing import Dict

# todo: 优化docker-compose

# 项目根目录
PROJECT_ROOT: str = os.path.realpath('../')
# 模板目录
TEMPLATE_PATH: str = os.path.join(PROJECT_ROOT, 'docker/template')
# venv bin 路径
VENV_BIN_PATH = '/venv/bin'
# 语言
language: str
# 当前语言配置
current_config: 'DockerConfig'


class DockerConfig:
    def __init__(self, source_path, run_file='ProxyCat-V1.9.py',
                 pip_install_cmd=f'{VENV_BIN_PATH}/pip install --no-cache-dir -r requirements.txt'):
        # 源代码路径，因每个语言项目目录不同，所以需要传入项目根目录
        self.source_path = os.path.join(PROJECT_ROOT, source_path)
        # pip install命令
        self.pip_install_cmd = pip_install_cmd
        # 启动文件
        self.run_file = run_file

    def get_template_fields4dockerfile(self):
        return {
            'run_file': self.run_file,
            'pip_install_cmd': self.pip_install_cmd
        }

    def get_template_fields4docker_compose(self):
        return {
            'none': None
        }


configs: Dict[str, DockerConfig] = {
    'CN': DockerConfig(source_path='ProxyCat-CN',
                       # 符合中国宝宝体质
                       pip_install_cmd=f'{VENV_BIN_PATH}/pip install --no-cache-dir -r requirements.txt' \
                                       ' -i https://pypi.tuna.tsinghua.edu.cn/simple/'),
    'EN': DockerConfig(source_path='ProxyCat-EN')
}


def get_args():
    import argparse
    parser = argparse.ArgumentParser(description='a generate docker compose file tool')
    parser.add_argument('-l', '--language', default='CN', help="LANGUAGE(support: CN, EN),default: CN")
    return parser.parse_args()


def get_template(template_name: str) -> str:
    with open(os.path.join(TEMPLATE_PATH, template_name), 'r') as f:
        return f.read()


def write_file(file_name, content: str):
    def w_f(p):
        with open(p, 'w') as f:
            f.write(content)
            logging.info(f"write {p} success")

    # 文件路径
    f_p = os.path.join(current_config.source_path, file_name)
    # 目录不存在报错
    if not os.path.exists(os.path.dirname(f_p)):
        logging.error(f"{os.path.dirname(f_p)} dir is not exists")
    if os.path.exists(f_p):
        logging.warning(f"{f_p} is exists")
        confirm = input(f'{f_p} is exists, overwrite?(Y/n)')
        if confirm.strip().lower() == 'y' or confirm.strip() == '':
            w_f(f_p)
        else:
            logging.info(f"{f_p} is not overwrite")
    else:
        w_f(f_p)


def generate_docker_compose():
    t = get_template('docker-compose_template')
    dockerfile_content = t.format(
        **current_config.get_template_fields4docker_compose()
    )
    write_file('docker-compose.yml', dockerfile_content)


def generate_docker_file():
    t = get_template('Dockerfile_template')
    dockerfile_content = t.format(
        **current_config.get_template_fields4dockerfile()
    )
    write_file('Dockerfile', dockerfile_content)


def get_test_cmd():
    return \
            f'docker: \n' + \
            f'\tcd {current_config.source_path} \n' + \
            f'\tdocker build -t proxycat:latest . \n' + \
            f'\tdocker run -it proxycat:latest -h\n' + \
            f'docker-compose\n' + \
            f'\tcd {current_config.source_path} \n' + \
            f'\tdocker-compose up -d'


def init(args):
    global language, current_config
    language = args.language.upper()
    current_config = configs.get(language)


if __name__ == '__main__':
    the_args = get_args()
    init(the_args)
    generate_docker_file()
    generate_docker_compose()
    print(get_test_cmd())
