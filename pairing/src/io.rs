//! Simple abstractions for the IO operations.
//!
//! Basically it just a replacement for the std::io that is usable from
//! the `no_std` environment.

/// IO specific error.
#[derive(Debug)]
pub enum Error {
	/// Some unexpected data left in the buffer after reading all data.
	TrailingData,

 	/// Unexpected End-Of-File
	UnexpectedEof,

 	/// Invalid data is encountered.
	InvalidData,

 	/// Failed to write whole buffer.
	WriteZero,

 	#[cfg(feature = "std")]
	IoError(::std::io::Error),
}

/// IO specific Result.
pub type Result<T> = ::std::result::Result<T, Error>;

 pub trait Write {
	/// Write a buffer of data into this write.
	///
	/// All data is written at once.
	fn write(&mut self, buf: &[u8]) -> Result<()>;
}

 pub trait Read {
	/// Read a data from this read to a buffer.
	///
	/// If there is not enough data in this read then `UnexpectedEof` will be returned.
	fn read(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// Reader that saves the last position.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Cursor<T> {
	inner: T,
	pos: usize,
}

 impl<T> Cursor<T> {
	pub fn new(inner: T) -> Cursor<T> {
		Cursor {
			inner,
			pos: 0,
		}
	}

 	pub fn position(&self) -> usize {
		self.pos
	}
}

 impl<T: AsRef<[u8]>> Read for Cursor<T> {
	fn read(&mut self, buf: &mut [u8]) -> Result<()> {
		let slice = self.inner.as_ref();
		let remainder = slice.len() - self.pos;
		let requested = buf.len();
		if requested > remainder {
			return Err(Error::UnexpectedEof);
		}
		buf.copy_from_slice(&slice[self.pos..(self.pos + requested)]);
		self.pos += requested;
		Ok(())
	}
}

 #[cfg(not(feature = "std"))]
impl Write for ::std::vec::Vec<u8> {
	fn write(&mut self, buf: &[u8]) -> Result<()> {
		self.extend(buf);
		Ok(())
	}
}

 #[cfg(not(feature = "std"))]
impl<'a> Write for &'a mut [u8] {
	fn write(&mut self, data: &[u8]) -> Result<()> {
		let amt = ::std::cmp::min(data.len(), self.len());
        let (a, b) = ::std::mem::replace(self, &mut []).split_at_mut(amt);
        a.copy_from_slice(&data[..amt]);
        *self = b;
		if amt == data.len() {
			Ok(())
		} else {
			Err(Error::WriteZero)
		}
	}
}

 #[cfg(not(feature = "std"))]
impl<'a> Read for &'a [u8] {
	fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.len() > self.len() {
            return Err(Error::UnexpectedEof);
        }
        let (a, b) = self.split_at(buf.len());

        // First check if the amount of bytes we want to read is small:
        // `copy_from_slice` will generally expand to a call to `memcpy`, and
        // for a single byte the overhead is significant.
        if buf.len() == 1 {
            buf[0] = a[0];
        } else {
            buf.copy_from_slice(a);
        }

         *self = b;
        Ok(())
	}
}

 #[cfg(feature = "std")]
impl<T: ::std::io::Read> Read for T {
	fn read(&mut self, buf: &mut [u8]) -> Result<()> {
		self.read_exact(buf)
			.map_err(Error::IoError)
	}
}

 #[cfg(feature = "std")]
impl<T: ::std::io::Write> Write for T {
	fn write(&mut self, buf: &[u8]) -> Result<()> {
		self.write_all(buf).map_err(Error::IoError)
	}
}

 #[cfg(test)]
mod tests {
	use super::*;

 	#[test]
	fn cursor() {
		let mut cursor = Cursor::new(vec![0xFFu8, 0x7Fu8]);
		assert_eq!(cursor.position(), 0);

 		let mut buf = [0u8];
		assert!(cursor.read(&mut buf[..]).is_ok());
		assert_eq!(cursor.position(), 1);
		assert_eq!(buf[0], 0xFFu8);
		assert!(cursor.read(&mut buf[..]).is_ok());
		assert_eq!(buf[0], 0x7Fu8);
		assert_eq!(cursor.position(), 2);
	}

 	#[test]
	fn overflow_in_cursor() {
		let mut cursor = Cursor::new(vec![0u8]);
		let mut buf = [0, 1, 2];
		assert!(cursor.read(&mut buf[..]).is_err());
	}
}
