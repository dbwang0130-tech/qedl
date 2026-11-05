//! 极简 Firehose XML 解析。只处理 `<response .../>` 和 `<log value="..."/>`。
//! Firehose 响应是 ASCII,结构简单,不引入重型 XML 依赖。

use std::collections::HashMap;

/// 从一段文本里提取某元素(如 "response"/"log")的所有属性键值对,返回第一个匹配元素。
pub fn attrs_of(data: &str, elem: &str) -> Option<HashMap<String, String>> {
    let needle = format!("<{}", elem);
    let start = data.find(&needle)?;
    // 元素属性区间到下一个 '>'。
    let rest = &data[start + needle.len()..];
    let endrel = rest.find('>')?;
    let body = &rest[..endrel];
    Some(parse_attrs(body))
}

fn parse_attrs(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // 跳到一个属性名起点(字母/下划线)
        while i < bytes.len() && !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
        {
            i += 1;
        }
        if name_start == i {
            break;
        }
        let name = &body[name_start..i];
        // 跳过空白
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1; // '='
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            continue;
        }
        i += 1; // 开引号
        let val_start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        let val = &body[val_start..i.min(bytes.len())];
        i += 1; // 闭引号
        map.insert(name.to_string(), val.to_string());
    }
    map
}

/// 返回 `<response>` 的 value 属性和全部属性。
pub fn response(data: &str) -> Option<(String, HashMap<String, String>)> {
    let a = attrs_of(data, "response")?;
    let v = a.get("value").cloned().unwrap_or_default();
    Some((v, a))
}

/// 所有 `<log value="..."/>` 的值。
pub fn logs(data: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(rel) = data[idx..].find("<log") {
        let abs = idx + rel;
        let rest = &data[abs..];
        if let Some(endrel) = rest.find('>') {
            let body = &rest[..endrel];
            let a = parse_attrs(body);
            if let Some(v) = a.get("value") {
                out.push(v.clone());
            }
            idx = abs + endrel + 1;
        } else {
            break;
        }
    }
    out
}

/// 字节转 lossy 字符串,方便匹配。
pub fn to_str(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}
