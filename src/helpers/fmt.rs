use std::fmt;

pub fn hide_content<T>(_: &T, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[hidden]")
}
