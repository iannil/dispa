//! 路由动作定义
//!
//! 本模块包含路由系统中的各种动作和转换结构体。

use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 路由动作集合
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingActions {
    /// 头部修改动作
    pub headers: Option<HeaderActions>,
    /// 路径修改动作
    pub path: Option<PathActions>,
    /// 请求体转换
    pub body_transformation: Option<BodyTransformation>,
    /// 请求转换（向后兼容）
    pub request_transform: Option<BodyTransformation>,
    /// 响应转换（向后兼容）
    pub response_transform: Option<BodyTransformation>,
}

/// 头部动作
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderActions {
    /// 要添加的头部
    #[serde(default)]
    pub add: HashMap<String, String>,
    /// 要移除的头部名称
    #[serde(default)]
    pub remove: Vec<String>,
    /// 要设置的头部（覆盖现有值）
    #[serde(default)]
    pub set: HashMap<String, String>,
}

/// 路径动作
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathActions {
    /// 路径前缀替换
    pub replace_prefix: Option<RegexReplace>,
    /// 路径后缀替换
    pub replace_suffix: Option<RegexReplace>,
    /// 完整路径正则表达式替换
    pub regex_replace: Option<RegexReplace>,
    /// 添加路径前缀
    pub add_prefix: Option<String>,
    /// 添加路径后缀
    pub add_suffix: Option<String>,
}

/// 正则表达式替换配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexReplace {
    /// 要匹配的正则表达式模式
    pub pattern: String,
    /// 替换字符串
    pub replacement: String,
}

/// 请求体转换配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyTransformation {
    /// 转换类型
    pub transformation_type: TransformationType,
    /// 转换参数（根据类型而定）
    pub parameters: Option<HashMap<String, serde_json::Value>>,
}

/// 转换类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformationType {
    /// JSON字段转换
    JsonTransform,
    /// 文本替换
    TextReplace,
    /// Base64编码
    Base64Encode,
    /// Base64解码
    Base64Decode,
    /// 自定义Lua脚本（如果支持）
    LuaScript,
    /// JSONPath操作
    JsonPath {
        /// JSONPath操作列表
        operations: Vec<JsonOperation>,
    },
}

/// JSON操作定义
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonOperation {
    /// 设置字段值
    Set {
        path: String,
        value: serde_json::Value,
    },
    /// 删除字段
    Remove { path: String },
    /// 重命名字段
    Rename { from: String, to: String },
    /// 添加字段（如果不存在）
    Add {
        path: String,
        value: serde_json::Value,
    },
}

/// 自定义响应配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResponse {
    /// HTTP状态码
    pub status_code: u16,
    /// 响应头部
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// 响应体内容
    pub body: Option<String>,
    /// 响应体内容类型
    pub content_type: Option<String>,
}

impl CustomResponse {
    /// 转换为Hyper响应
    #[allow(dead_code)]
    pub fn to_hyper_response(&self) -> Result<hyper::Response<hyper::Body>, hyper::http::Error> {
        let mut response = hyper::Response::builder()
            .status(StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::OK));

        // 添加头部
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }

        // 设置内容类型
        if let Some(content_type) = &self.content_type {
            response = response.header("content-type", content_type);
        }

        // 设置响应体
        let body = self.body.clone().unwrap_or_default();
        response.body(hyper::Body::from(body))
    }
}
