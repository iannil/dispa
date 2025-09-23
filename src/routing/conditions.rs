//! 路由条件定义
//!
//! 本模块包含用于路由决策的各种条件结构体。

use serde::{Deserialize, Serialize};

/// 路由条件集合
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConditions {
    /// 路径相关条件
    pub path: Option<PathConditions>,
    /// HTTP方法条件
    pub method: Option<Vec<String>>,
    /// 头部条件
    pub headers: Option<Vec<HeaderCondition>>,
    /// 查询参数条件
    pub query_params: Option<Vec<QueryParamCondition>>,
    /// 主机条件
    pub host: Option<HostCondition>,
}

/// 路径匹配条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConditions {
    /// 精确路径匹配
    pub exact: Option<String>,
    /// 路径前缀匹配
    pub prefix: Option<String>,
    /// 路径后缀匹配
    pub suffix: Option<String>,
    /// 正则表达式匹配
    pub regex: Option<String>,
    /// 路径包含指定字符串
    pub contains: Option<String>,
}

/// 头部条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderCondition {
    /// 头部名称
    pub name: String,
    /// 头部值匹配模式
    pub value: Option<HeaderValueMatch>,
    /// 头部值正则表达式匹配
    pub value_regex: Option<String>,
    /// 检查头部是否存在
    #[serde(default)]
    pub exists: bool,
}

/// 头部值匹配枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderValueMatch {
    /// 精确匹配单个值
    Exact(String),
    /// 匹配多个可能的值之一
    OneOf(Vec<String>),
    /// 包含指定子字符串
    Contains { contains: String },
    /// 以指定前缀开头
    StartsWith { starts_with: String },
    /// 以指定后缀结尾
    EndsWith { ends_with: String },
}

/// 查询参数条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParamCondition {
    /// 参数名称
    pub name: String,
    /// 参数值（可选，如果为None则只检查参数存在性）
    pub value: Option<String>,
    /// 参数值正则表达式匹配
    pub value_regex: Option<String>,
}

/// 主机条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCondition {
    /// 精确主机匹配
    pub exact: Option<String>,
    /// 主机正则表达式匹配
    pub regex: Option<String>,
    /// 主机包含指定子字符串
    pub contains: Option<String>,
}
