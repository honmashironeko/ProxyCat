"""
模块名称：modules.proxypool.core.services.geo_names
功能描述：归属地名称的翻译与回退：把规范国码 / 细分代码与多语言名字渲染成中英两套可展示名称，缺译名时回退为另一语言的原文。
职责边界：负责：名称对照表、按语言渲染名称、标记未翻译的原文；不负责：查 IP（见 geodb）、缓存（见 geoip 服务）、写库（见 geo_resolver）。
关键依赖：core.domain.models（GeoName / GeoRecord）；标准库 typing。
已知限制：
  1. 对照表为有限集，未收录的行政区回退为另一语言的原文并置对应的 untranslated 标记，译名覆盖不保证完整。
  2. 一级行政区只按 ISO 3166-2 细分代码建键，subdivision_zh 查询前把国码与细分码转大写，代码缺失时返回 None。
  3. 中文短名查英文表前会剥后缀：china_province_en 反复剥省 / 市 / 自治区 / 特别行政区与民族后缀，china_city_en 只剥一个「市」，长名可能查不到。
  4. render_names 各字段独立回退，中英两侧都取不到译名时会显示同一个值，untranslated 的单个布尔无法区分哪一侧取到的是原文。
  5. 国码字段没有对照表回退，仅一侧有名字时两侧显示同一文本，untranslated["country"] 表示恰好一侧为空。
  6. 非中国记录的英文省与城市字段不做中文回退，可能保持 UNKNOWN 且不置对应标记；UNKNOWN（「未知」）是任何一段都可能返回的占位串。
"""

import logging
from typing import Mapping, Optional

from core.domain.models import GeoName, GeoRecord

logger = logging.getLogger(__name__)

CHINA_PROVINCE_EN: Mapping[str, str] = {
    "北京": "Beijing", "天津": "Tianjin", "河北": "Hebei", "山西": "Shanxi",
    "内蒙古": "Inner Mongolia", "辽宁": "Liaoning", "吉林": "Jilin",
    "黑龙江": "Heilongjiang", "上海": "Shanghai", "江苏": "Jiangsu",
    "浙江": "Zhejiang", "安徽": "Anhui", "福建": "Fujian", "江西": "Jiangxi",
    "山东": "Shandong", "河南": "Henan", "湖北": "Hubei", "湖南": "Hunan",
    "广东": "Guangdong", "广西": "Guangxi", "海南": "Hainan", "重庆": "Chongqing",
    "四川": "Sichuan", "贵州": "Guizhou", "云南": "Yunnan", "西藏": "Tibet",
    "陕西": "Shaanxi", "甘肃": "Gansu", "青海": "Qinghai", "宁夏": "Ningxia",
    "新疆": "Xinjiang", "香港": "Hong Kong", "澳门": "Macau", "台湾": "Taiwan",
}

CHINA_CITY_EN: Mapping[str, str] = {
    "北京": "Beijing", "上海": "Shanghai", "天津": "Tianjin", "重庆": "Chongqing",
    "石家庄": "Shijiazhuang", "太原": "Taiyuan", "呼和浩特": "Hohhot",
    "沈阳": "Shenyang", "长春": "Changchun", "哈尔滨": "Harbin",
    "南京": "Nanjing", "杭州": "Hangzhou", "合肥": "Hefei", "福州": "Fuzhou",
    "南昌": "Nanchang", "济南": "Jinan", "郑州": "Zhengzhou", "武汉": "Wuhan",
    "长沙": "Changsha", "广州": "Guangzhou", "南宁": "Nanning", "海口": "Haikou",
    "成都": "Chengdu", "贵阳": "Guiyang", "昆明": "Kunming", "拉萨": "Lhasa",
    "西安": "Xi'an", "兰州": "Lanzhou", "西宁": "Xining", "银川": "Yinchuan",
    "乌鲁木齐": "Urumqi", "台北": "Taipei", "香港": "Hong Kong", "澳门": "Macau",
    "深圳": "Shenzhen", "厦门": "Xiamen", "宁波": "Ningbo", "青岛": "Qingdao",
    "大连": "Dalian", "苏州": "Suzhou", "无锡": "Wuxi", "温州": "Wenzhou",
    "佛山": "Foshan", "东莞": "Dongguan", "珠海": "Zhuhai", "汕头": "Shantou",
    "泉州": "Quanzhou", "烟台": "Yantai", "潍坊": "Weifang", "徐州": "Xuzhou",
    "常州": "Changzhou", "南通": "Nantong", "扬州": "Yangzhou", "盐城": "Yancheng",
    "泰州": "Taizhou", "镇江": "Zhenjiang", "绍兴": "Shaoxing", "嘉兴": "Jiaxing",
    "台州": "Taizhou", "金华": "Jinhua", "湖州": "Huzhou", "丽水": "Lishui",
    "衢州": "Quzhou", "舟山": "Zhoushan", "芜湖": "Wuhu", "蚌埠": "Bengbu",
    "洛阳": "Luoyang", "新乡": "Xinxiang", "开封": "Kaifeng",
    "南阳": "Nanyang", "商丘": "Shangqiu", "周口": "Zhoukou", "信阳": "Xinyang",
    "襄阳": "Xiangyang", "宜昌": "Yichang", "荆州": "Jingzhou", "黄石": "Huangshi",
    "十堰": "Shiyan", "株洲": "Zhuzhou", "湘潭": "Xiangtan", "衡阳": "Hengyang",
    "岳阳": "Yueyang", "常德": "Changde", "郴州": "Chenzhou",
    "中山": "Zhongshan", "江门": "Jiangmen", "湛江": "Zhanjiang", "茂名": "Maoming",
    "肇庆": "Zhaoqing", "揭阳": "Jieyang", "潮州": "Chaozhou", "梅州": "Meizhou",
    "惠州": "Huizhou", "河源": "Heyuan", "清远": "Qingyuan", "韶关": "Shaoguan",
    "阳江": "Yangjiang", "云浮": "Yunfu", "汕尾": "Shanwei", "桂林": "Guilin",
    "柳州": "Liuzhou", "北海": "Beihai", "三亚": "Sanya", "绵阳": "Mianyang",
    "德阳": "Deyang", "宜宾": "Yibin", "泸州": "Luzhou", "南充": "Nanchong",
    "遵义": "Zunyi", "曲靖": "Qujing", "大理": "Dali", "咸阳": "Xianyang",
    "宝鸡": "Baoji", "渭南": "Weinan", "榆林": "Yulin", "天水": "Tianshui",
    "包头": "Baotou", "鄂尔多斯": "Ordos", "赤峰": "Chifeng", "大庆": "Daqing",
    "齐齐哈尔": "Qiqihar", "吉林": "Jilin", "鞍山": "Anshan", "抚顺": "Fushun",
    "锦州": "Jinzhou", "营口": "Yingkou", "唐山": "Tangshan", "保定": "Baoding",
    "廊坊": "Langfang", "秦皇岛": "Qinhuangdao", "邯郸": "Handan", "沧州": "Cangzhou",
    "邢台": "Xingtai", "张家口": "Zhangjiakou", "承德": "Chengde", "大同": "Datong",
    "临汾": "Linfen", "运城": "Yuncheng", "长治": "Changzhi", "晋中": "Jinzhong",
    "赣州": "Ganzhou", "九江": "Jiujiang", "上饶": "Shangrao", "宜春": "Yichun",
    "吉安": "Ji'an", "抚州": "Fuzhou", "景德镇": "Jingdezhen", "萍乡": "Pingxiang",
    "新余": "Xinyu", "鹰潭": "Yingtan", "莆田": "Putian", "三明": "Sanming",
    "南平": "Nanping", "龙岩": "Longyan", "宁德": "Ningde", "漳州": "Zhangzhou",
}

SUBDIVISION_ZH: Mapping[tuple, str] = {
    ("US", "AL"): "亚拉巴马州", ("US", "AK"): "阿拉斯加州", ("US", "AZ"): "亚利桑那州",
    ("US", "AR"): "阿肯色州", ("US", "CA"): "加利福尼亚州", ("US", "CO"): "科罗拉多州",
    ("US", "CT"): "康涅狄格州", ("US", "DE"): "特拉华州", ("US", "DC"): "哥伦比亚特区",
    ("US", "FL"): "佛罗里达州", ("US", "GA"): "佐治亚州", ("US", "HI"): "夏威夷州",
    ("US", "ID"): "爱达荷州", ("US", "IL"): "伊利诺伊州", ("US", "IN"): "印第安纳州",
    ("US", "IA"): "艾奥瓦州", ("US", "KS"): "堪萨斯州", ("US", "KY"): "肯塔基州",
    ("US", "LA"): "路易斯安那州", ("US", "ME"): "缅因州", ("US", "MD"): "马里兰州",
    ("US", "MA"): "马萨诸塞州", ("US", "MI"): "密歇根州", ("US", "MN"): "明尼苏达州",
    ("US", "MS"): "密西西比州", ("US", "MO"): "密苏里州", ("US", "MT"): "蒙大拿州",
    ("US", "NE"): "内布拉斯加州", ("US", "NV"): "内华达州", ("US", "NH"): "新罕布什尔州",
    ("US", "NJ"): "新泽西州", ("US", "NM"): "新墨西哥州", ("US", "NY"): "纽约州",
    ("US", "NC"): "北卡罗来纳州", ("US", "ND"): "北达科他州", ("US", "OH"): "俄亥俄州",
    ("US", "OK"): "俄克拉何马州", ("US", "OR"): "俄勒冈州", ("US", "PA"): "宾夕法尼亚州",
    ("US", "RI"): "罗得岛州", ("US", "SC"): "南卡罗来纳州", ("US", "SD"): "南达科他州",
    ("US", "TN"): "田纳西州", ("US", "TX"): "得克萨斯州", ("US", "UT"): "犹他州",
    ("US", "VT"): "佛蒙特州", ("US", "VA"): "弗吉尼亚州", ("US", "WA"): "华盛顿州",
    ("US", "WV"): "西弗吉尼亚州", ("US", "WI"): "威斯康星州", ("US", "WY"): "怀俄明州",
    ("JP", "01"): "北海道", ("JP", "02"): "青森县", ("JP", "03"): "岩手县",
    ("JP", "04"): "宫城县", ("JP", "05"): "秋田县", ("JP", "06"): "山形县",
    ("JP", "07"): "福岛县", ("JP", "08"): "茨城县", ("JP", "09"): "栃木县",
    ("JP", "10"): "群马县", ("JP", "11"): "埼玉县", ("JP", "12"): "千叶县",
    ("JP", "13"): "东京都", ("JP", "14"): "神奈川县", ("JP", "15"): "新潟县",
    ("JP", "16"): "富山县", ("JP", "17"): "石川县", ("JP", "18"): "福井县",
    ("JP", "19"): "山梨县", ("JP", "20"): "长野县", ("JP", "21"): "岐阜县",
    ("JP", "22"): "静冈县", ("JP", "23"): "爱知县", ("JP", "24"): "三重县",
    ("JP", "25"): "滋贺县", ("JP", "26"): "京都府", ("JP", "27"): "大阪府",
    ("JP", "28"): "兵库县", ("JP", "29"): "奈良县", ("JP", "30"): "和歌山县",
    ("JP", "31"): "鸟取县", ("JP", "32"): "岛根县", ("JP", "33"): "冈山县",
    ("JP", "34"): "广岛县", ("JP", "35"): "山口县", ("JP", "36"): "德岛县",
    ("JP", "37"): "香川县", ("JP", "38"): "爱媛县", ("JP", "39"): "高知县",
    ("JP", "40"): "福冈县", ("JP", "41"): "佐贺县", ("JP", "42"): "长崎县",
    ("JP", "43"): "熊本县", ("JP", "44"): "大分县", ("JP", "45"): "宫崎县",
    ("JP", "46"): "鹿儿岛县", ("JP", "47"): "冲绳县",
    ("KR", "11"): "首尔特别市", ("KR", "26"): "釜山广域市", ("KR", "27"): "大邱广域市",
    ("KR", "28"): "仁川广域市", ("KR", "29"): "光州广域市", ("KR", "30"): "大田广域市",
    ("KR", "31"): "蔚山广域市", ("KR", "41"): "京畿道", ("KR", "42"): "江原特别自治道",
    ("KR", "43"): "忠清北道", ("KR", "44"): "忠清南道", ("KR", "45"): "全北特别自治道",
    ("KR", "46"): "全罗南道", ("KR", "47"): "庆尚北道", ("KR", "48"): "庆尚南道",
    ("KR", "49"): "济州特别自治道", ("KR", "50"): "世宗特别自治市",
    ("CA", "AB"): "艾伯塔省", ("CA", "BC"): "不列颠哥伦比亚省", ("CA", "MB"): "曼尼托巴省",
    ("CA", "NB"): "新不伦瑞克省", ("CA", "NL"): "纽芬兰与拉布拉多省",
    ("CA", "NS"): "新斯科舍省", ("CA", "NT"): "西北地区", ("CA", "NU"): "努纳武特地区",
    ("CA", "ON"): "安大略省", ("CA", "PE"): "爱德华王子岛省", ("CA", "QC"): "魁北克省",
    ("CA", "SK"): "萨斯喀彻温省", ("CA", "YT"): "育空地区",
    ("AU", "ACT"): "澳大利亚首都领地", ("AU", "NSW"): "新南威尔士州",
    ("AU", "NT"): "北领地", ("AU", "QLD"): "昆士兰州", ("AU", "SA"): "南澳大利亚州",
    ("AU", "TAS"): "塔斯马尼亚州", ("AU", "VIC"): "维多利亚州",
    ("AU", "WA"): "西澳大利亚州",
    ("GB", "ENG"): "英格兰", ("GB", "SCT"): "苏格兰", ("GB", "WLS"): "威尔士",
    ("GB", "NIR"): "北爱尔兰",
    ("DE", "BW"): "巴登-符腾堡州", ("DE", "BY"): "巴伐利亚州", ("DE", "BE"): "柏林州",
    ("DE", "BB"): "勃兰登堡州", ("DE", "HB"): "不来梅州", ("DE", "HH"): "汉堡州",
    ("DE", "HE"): "黑森州", ("DE", "MV"): "梅克伦堡-前波美拉尼亚州",
    ("DE", "NI"): "下萨克森州", ("DE", "NW"): "北莱茵-威斯特法伦州",
    ("DE", "RP"): "莱茵兰-普法尔茨州", ("DE", "SL"): "萨尔州", ("DE", "SN"): "萨克森州",
    ("DE", "ST"): "萨克森-安哈尔特州", ("DE", "SH"): "石勒苏益格-荷尔斯泰因州",
    ("DE", "TH"): "图林根州",
    ("FR", "IDF"): "法兰西岛大区", ("FR", "ARA"): "奥弗涅-罗讷-阿尔卑斯大区",
    ("FR", "BFC"): "勃艮第-弗朗什-孔泰大区", ("FR", "BRE"): "布列塔尼大区",
    ("FR", "CVL"): "中央-卢瓦尔河谷大区", ("FR", "COR"): "科西嘉大区",
    ("FR", "GES"): "大东部大区", ("FR", "HDF"): "上法兰西大区",
    ("FR", "NOR"): "诺曼底大区", ("FR", "NAQ"): "新阿基坦大区",
    ("FR", "OCC"): "奥克西塔尼大区", ("FR", "PDL"): "卢瓦尔河地区大区",
    ("FR", "PAC"): "普罗旺斯-阿尔卑斯-蔚蓝海岸大区",
    ("NL", "NH"): "北荷兰省", ("NL", "ZH"): "南荷兰省", ("NL", "UT"): "乌得勒支省",
    ("NL", "NB"): "北布拉班特省", ("NL", "GE"): "海尔德兰省", ("NL", "OV"): "上艾瑟尔省",
    ("NL", "FR"): "弗里斯兰省", ("NL", "GR"): "格罗宁根省", ("NL", "DR"): "德伦特省",
    ("NL", "FL"): "弗莱福兰省", ("NL", "ZE"): "泽兰省", ("NL", "LI"): "林堡省",
    ("SG", "01"): "中区", ("SG", "02"): "东北区", ("SG", "03"): "西北区",
    ("SG", "04"): "东南区", ("SG", "05"): "西南区",
    ("HK", "HK"): "香港", ("MO", "MO"): "澳门",
    ("TW", "TPE"): "台北市", ("TW", "TPQ"): "新北市", ("TW", "TXG"): "台中市",
    ("TW", "TNN"): "台南市", ("TW", "KHH"): "高雄市", ("TW", "HSZ"): "新竹市",
    ("TW", "HSQ"): "新竹县", ("TW", "TAO"): "桃园市", ("TW", "ILA"): "宜兰县",
    ("TW", "KEE"): "基隆市", ("TW", "CYI"): "嘉义市", ("TW", "CYQ"): "嘉义县",
    ("TW", "CHA"): "彰化县", ("TW", "YUN"): "云林县", ("TW", "NAN"): "南投县",
    ("TW", "PIF"): "屏东县", ("TW", "TTT"): "台东县", ("TW", "HUA"): "花莲县",
    ("TW", "PEN"): "澎湖县", ("TW", "MIA"): "苗栗县",
}

_CN_PROVINCE_SUFFIXES = ("省", "市", "自治区", "特别行政区", "壮族", "回族", "维吾尔")

UNKNOWN = "未知"


def _strip_cn_suffix(name: str) -> str:
    result = name
    changed = True
    while changed:
        changed = False
        for suffix in _CN_PROVINCE_SUFFIXES:
            if result.endswith(suffix) and len(result) > len(suffix):
                result = result[: -len(suffix)]
                changed = True
    return result


def subdivision_zh(country_code: str, subdivision_code: str) -> Optional[str]:
    if not country_code or not subdivision_code:
        return None
    return SUBDIVISION_ZH.get((country_code.upper(), subdivision_code.upper()))


def china_province_en(name_zh: str) -> Optional[str]:
    if not name_zh:
        return None
    return CHINA_PROVINCE_EN.get(name_zh) or CHINA_PROVINCE_EN.get(_strip_cn_suffix(name_zh))


def china_city_en(name_zh: str) -> Optional[str]:
    if not name_zh:
        return None
    short = name_zh[:-1] if name_zh.endswith("市") else name_zh
    return CHINA_CITY_EN.get(name_zh) or CHINA_CITY_EN.get(short)


def render_names(record: GeoRecord) -> tuple:
    country_code = record.country_code
    sub_code = record.subdivision_code

    zh_country_text = record.country_names.get("zh-CN") or ""
    en_country_text = record.country_names.get("en") or ""

    untranslated = {"country": False, "province": False, "city": False}
    untranslated["country"] = bool(zh_country_text) != bool(en_country_text)

    zh_country = zh_country_text or en_country_text or UNKNOWN
    en_country = en_country_text or zh_country_text or UNKNOWN

    zh_sub = record.subdivision_names.get("zh-CN") or ""
    if not zh_sub:
        zh_sub = subdivision_zh(country_code, sub_code) or ""
        if not zh_sub:
            zh_sub = record.subdivision_names.get("en") or ""
            untranslated["province"] = bool(zh_sub)

    en_sub = record.subdivision_names.get("en") or ""
    if record.is_china and not en_sub:
        en_sub = china_province_en(zh_sub) or ""
        if not en_sub:
            en_sub = zh_sub
            untranslated["province"] = bool(en_sub)

    zh_city = record.city_names.get("zh-CN") or ""
    if not zh_city:
        zh_city = record.city_names.get("en") or ""
        if zh_city:
            untranslated["city"] = True

    en_city = record.city_names.get("en") or ""
    if record.is_china and not en_city:
        en_city = china_city_en(zh_city) or ""
        if not en_city:
            en_city = zh_city
            untranslated["city"] = bool(en_city)

    zh = GeoName(country=zh_country, province=zh_sub or UNKNOWN, city=zh_city or UNKNOWN)
    en = GeoName(country=en_country, province=en_sub or UNKNOWN, city=en_city or UNKNOWN)
    return zh, en, untranslated
