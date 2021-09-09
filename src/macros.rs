macro_rules! pinpoint {
    ($error:expr, $location:expr) => {
        crate::error::Error::pinpoint($error, $location)
    };
    ($error:expr, $location:expr, $tag:expr) => {
        crate::error::Error::pinpoint_with_tag($error, $location, $tag)
    };
    ($error:expr, $location:expr, $tag:expr, $ty:expr) => {
        crate::error::Error::pinpoint_with_tag_and_type($error, $location, $tag, $ty)
    };
}
