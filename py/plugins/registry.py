#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""插件注册表"""
from py.plugins.autojs import decrypt as autojs_dec
from py.plugins.qmacro import decrypt as qmacro_dec
from py.plugins.touchsprite import decrypt as touch_dec
from py.plugins.hamibot import decrypt as hamibot_dec
from py.plugins.js_deobf import decrypt as jsobf_dec
from py.plugins.buxianxian import decrypt_bytes as bxxian_dec
from py.plugins.prometheus import decrypt as prom_dec

EXT_RULES=[
 (".enc","AutoJS加密",autojs_dec),(".q","按键.q",qmacro_dec),
 (".qmc","按键.qmc",qmacro_dec),(".mq","按键手机",qmacro_dec),
 (".luac","触动Lua",touch_dec),(".tsproj","触动项目",touch_dec),
 (".lua","Lua脚本",touch_dec),(".hamibot","Hamibot",hamibot_dec)]

CONTENT_RULES=[
 (b"RC4RRR","不羡仙gg-Lua",bxxian_dec),(b"auto.js","AutoJS",autojs_dec),
 (b"autojs","AutoJS",autojs_dec),(b"hamibot","Hamibot",hamibot_dec),
 (b"touchsprite","触动精灵",touch_dec),(b"KeyPress","按键精灵",qmacro_dec),
 (b"_0x","JS混淆",jsobf_dec)]
