package detector

import (
	"gowaf/internal/domain/security/dlprule"
)

var dlpReverseMapping = map[string]string{
	"银行卡号(16位)":      "credit_card",
	"银行卡号(19位)":      "credit_card",
	"中国大陆手机号":        "phone_cn",
	"中国身份证号":         "id_card_cn",
	"密码字段(常见key)":    "api_key",
	"私钥标识":           "private_key",
	"AWS Access Key": "aws_key",
	"电子邮箱地址":         "email",
}

// adaptDLPResult 将DLP匹配结果适配为sensitive_data的返回格式
func adaptDLPResult(matches []dlprule.DLPMatch, location string) (bool, string, string, int, string) {
	for _, m := range matches {
		sensitiveName, ok := dlpReverseMapping[m.RuleName]
		if !ok {
			continue
		}
		return true, sensitiveName, location, 1, "敏感数据检测:" + sensitiveName + "(via DLP:" + m.RuleName + ")"
	}
	return false, "", "", 0, ""
}
