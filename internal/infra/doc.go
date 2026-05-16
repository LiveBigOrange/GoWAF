// Package infra 基础设施层，提供配置、存储、日志、通知等基础能力。
//
// 本包定义的接口供 domain 层通过接口依赖，实现依赖反转。
// 依赖规则：infra 仅可依赖 pkg，禁止依赖 domain。
package infra
