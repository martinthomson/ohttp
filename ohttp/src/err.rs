#[derive(Debug)]
pub enum Error {
    /// A problem occurred during cryptographic processing.
    Crypto(crate::nss::Error),
    /// An error was found in the format.
    Format,
    /// The wrong KEM was specified.
    InvalidKem,
    /// An IO error.
    Io(std::io::Error),
    /// The key ID was invalid.
    KeyId,
    /// A field was truncated.
    Truncated,
    /// The configuration was not supported.
    Unsupported,
}

macro_rules! forward_errors {
    {$($t:path => $v:ident),* $(,)?} => {
        $(
            impl From<$t> for Error {
                fn from(e: $t) -> Self {
                    Self::$v(e)
                }
            }
        )*

        impl std::error::Error for Error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $( Self::$v(e) => Some(e), )*
                    _ => None,
                }
            }
        }
    };
}

forward_errors! {
    crate::nss::Error => Crypto,
    std::io::Error => Io,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

pub type Res<T> = Result<T, Error>;
