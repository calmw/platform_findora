#![deny(warnings)]
//! findora
//!
//! This module implements a variety of tools for general use.

extern crate serde;
extern crate serde_derive;

use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::ptr::read_volatile;

pub mod dw;

/// This structure defines the table entries for the logging enable flags.
/// The table has one entry per category.
#[derive(Default)]
pub struct EnableMap {
  pub name: &'static str,
  log_enabled: bool,
  error_enabled: bool,
  warning_enabled: bool,
  debug_enabled: bool,
  info_enabled: bool,
}

impl EnableMap {
  // Set the flags
  pub fn set_log(&mut self, value: bool) {
    self.log_enabled = value;
  }

  pub fn set_error(&mut self, value: bool) {
    self.error_enabled = value;
  }

  pub fn set_warning(&mut self, value: bool) {
    self.warning_enabled = value;
  }

  pub fn set_debug(&mut self, value: bool) {
    self.debug_enabled = value;
  }

  pub fn set_info(&mut self, value: bool) {
    self.info_enabled = value;
  }

  // Check the flags.
  pub fn log_enabled(&self) -> bool {
    unsafe { read_volatile(&self.log_enabled as *const bool) }
  }

  pub fn error_enabled(&self) -> bool {
    unsafe { read_volatile(&self.error_enabled as *const bool) }
  }

  pub fn warning_enabled(&self) -> bool {
    unsafe { read_volatile(&self.warning_enabled as *const bool) }
  }

  pub fn debug_enabled(&self) -> bool {
    unsafe { read_volatile(&self.debug_enabled as *const bool) }
  }

  pub fn info_enabled(&self) -> bool {
    unsafe { read_volatile(&self.info_enabled as *const bool) }
  }
}

pub trait HasInvariants<ErrT> {
  // Simple sanity checks, preferably constant-time. Could be toggled in a production environment
  // without jeopardizing moderate performance requirements.
  fn fast_invariant_check(&self) -> Result<(), ErrT>;
  // Computationally intensive checks, intended for a testing environment.
  fn deep_invariant_check(&self) -> Result<(), ErrT>;
}

// TODO:  This table should be generated by a program.
/// This table lists all of the categories that the logging currently
/// supports.
pub static mut TABLE: [EnableMap; 11] = [EnableMap { name: "bitmap",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "append",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "proof",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "test",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "apply_log",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "find_relevant",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "store",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "ledger",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "issue",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "check_merkle",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false },
                                         EnableMap { name: "rebuild_merkle",
                                                     log_enabled: true,
                                                     error_enabled: true,
                                                     warning_enabled: true,
                                                     debug_enabled: false,
                                                     info_enabled: false }];

/// Define the list of all categories for logging messages.
pub enum Categories {
  Bitmap = 0,
  Append = 1,
  Proof = 2,
  Test = 3,
  ApplyLog = 4,
  FindRelevant = 5,
  Store = 6,
  Ledger = 7,
  Issue = 8,
  CheckMerkle = 9,
  RebuildMerkle = 10,
}

pub static mut TIMESTAMP: fn() -> String = timestamp;

/// Set the function that generates the timestamp applied to
/// log entries.
///
/// This function should be called at program startup time only,
/// when no logging is happening.
pub fn set_timestamp(f: fn() -> String) {
  unsafe {
    TIMESTAMP = f;
  }
}

/// Define the structure used to specify dynamic (runtime) changes
/// to the logging flags.
#[derive(Serialize, Deserialize)]
pub struct LoggingEnableFlags {
  pub name: String,

  pub log: bool,
  pub error: bool,
  pub warning: bool,
  pub debug: bool,
  pub info: bool,

  pub modify_log: bool,
  pub modify_error: bool,
  pub modify_warning: bool,
  pub modify_debug: bool,
  pub modify_info: bool,
}

/// Set the logging flags for a category at run time.
pub fn set_logging(flags: &LoggingEnableFlags) -> bool {
  unsafe {
    for entry in &mut TABLE {
      if entry.name == flags.name {
        if flags.modify_log {
          entry.set_log(flags.log);
        }

        if flags.modify_error {
          entry.set_error(flags.error);
        }

        if flags.modify_warning {
          entry.set_warning(flags.warning);
        }

        if flags.modify_debug {
          entry.set_debug(flags.debug);
        }

        if flags.modify_info {
          entry.set_info(flags.info);
        }

        return true;
      }
    }
  }

  false
}

// The log_impl macro calls println to output an actual
// log entry.  It is called by the macros intended for
// external use.
//
// At some point, we should enable dynamic replacement of
// this routine.
#[macro_export]
macro_rules! log_impl {
  ($level:ident, $category:ident, $enable:ident, $($x:tt)+) => {
    {
      use findora::TIMESTAMP;
      use findora::TABLE;
      use findora::Categories;

      unsafe {
        if TABLE[Categories::$category as usize].$enable() {
          println!("{}  {:10.10}  {:16.16}  {}",
            TIMESTAMP(), stringify!($level),
            TABLE[Categories::$category as usize].name,
            format!($($x)+));
        }
      }
    }
  }
}

/// Write a log entry when enabled.
#[macro_export]
macro_rules! error {
    ($category:ident, $($x:tt)+) => {
      log_impl!(error, $category, error_enabled, $($x)+);
    }
}

/// Write a debug log entry when enabled.
#[macro_export]
macro_rules! debug {
    ($category:ident, $($x:tt)+) => {
      log_impl!(error, $category, debug_enabled, $($x)+);
    }
}

/// Write a debug log entry when enabled.
#[macro_export]
macro_rules! warning {
    ($category:ident, $($x:tt)+) => {
      log_impl!(error, $category, warning_enabled, $($x)+);
    }
}

/// Write a debug log entry when enabled.
#[macro_export]
macro_rules! info {
    ($category:ident, $($x:tt)+) => {
      log_impl!(error, $category, info_enabled, $($x)+);
    }
}

/// Write a log entry.
#[macro_export]
macro_rules! log {
    ($category:ident, $($x:tt)+) => {
      log_impl!(error, $category, log_enabled, $($x)+);
    }
}

/// Returns Some(Error::...).
#[macro_export]
macro_rules! se {
    ($($x:tt)+) => { Some(Error::new(ErrorKind::Other, format!($($x)+))) }
}

/// Returns Err(Error::new...).
#[macro_export]
macro_rules! er {
    ($($x:tt)+) => { Err(Error::new(ErrorKind::Other, format!($($x)+))) }
}

/// Returns a deserializer error:  Err(serde::de::Error::...)
#[macro_export]
macro_rules! sde  {
    ($($x:tt)+) => {
        Err(serde::de::Error::custom(format!($($x)+)))
    }
}

/// Produce a timestamp of UTC down to milliseconds, with rounding.
/// This routine ignores leap seconds.
pub fn timestamp() -> String {
  use chrono::DateTime;
  use chrono::Datelike;
  use chrono::Timelike;
  use chrono::Utc;

  let now: DateTime<Utc> = Utc::now();

  format!("{:04}/{:02}/{:02}  {:02}:{:02}:{:02}.{:03} UTC",
          now.year(),
          now.month(),
          now.day(),
          now.hour(),
          now.minute(),
          now.second(),
          (now.nanosecond() + 500 * 1000) / (1000 * 1000))
}

/// Convert a u64 into a string with commas.
fn commas_u64(input: u64) -> String {
  if input < 10000 {
    return format!("{}", input);
  }

  let mut value = input;
  let mut result = "".to_string();

  while value > 1000 {
    result = format!(",{:03.3}", value % 1000) + &result;
    value /= 1000;
  }

  if value == 1000 {
    result = "1,000".to_owned() + &result;
  } else {
    result = format!("{}", value) + &result;
  }

  result
}

/// Convert an i64 into a string with commas.
fn commas_i64(input: i64) -> String {
  if input == 0 {
    return "0".to_string();
  }

  let sign = input < 0;
  let mut result;

  if input == std::i64::MIN {
    result = commas_u64(1u64 << 63);
  } else if input < 0 {
    result = commas_u64(-input as u64);
  } else {
    result = commas_u64(input as u64);
  }

  if sign {
    result = "-".to_owned() + &result;
  }

  result
}

pub trait Commas {
  fn commas(self) -> String;
}

impl Commas for u64 {
  fn commas(self) -> String {
    crate::commas_u64(self)
  }
}

impl Commas for u32 {
  fn commas(self) -> String {
    crate::commas_u64(self as u64)
  }
}

impl Commas for u16 {
  fn commas(self) -> String {
    crate::commas_u64(self as u64)
  }
}

impl Commas for u8 {
  fn commas(self) -> String {
    crate::commas_u64(self as u64)
  }
}

impl Commas for usize {
  fn commas(self) -> String {
    crate::commas_u64(self as u64)
  }
}

impl Commas for i64 {
  fn commas(self) -> String {
    crate::commas_i64(self)
  }
}

impl Commas for i32 {
  fn commas(self) -> String {
    crate::commas_i64(self as i64)
  }
}

impl Commas for i16 {
  fn commas(self) -> String {
    crate::commas_i64(self as i64)
  }
}

impl Commas for i8 {
  fn commas(self) -> String {
    crate::commas_i64(self as i64)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_commas() {
    // Test u64
    assert_eq!("0", 0u64.commas());
    assert_eq!("100", 100u64.commas());
    assert_eq!("999", 999u64.commas());
    assert_eq!("1000", 1000_u64.commas());
    assert_eq!("9999", 9999u64.commas());
    assert_eq!("10,000", 10000_u64.commas());
    assert_eq!("1,000,000", (1000u64 * 1000u64).commas());
    assert_eq!("1,048,576", (1024 * 1024_u64).commas());
    assert_eq!("999,000", (999 * 1000_u64).commas());
    assert_eq!("2000", (2 * 1000_u64).commas());
    assert_eq!("1,000,000,000", (1000 * 1000 * 1000_u64).commas());
    assert_eq!("18,446,744,073,709,551,615", std::u64::MAX.commas());

    // Test u32
    assert_eq!("0", 0u32.commas());
    assert_eq!("100", 100u32.commas());
    assert_eq!("999", 999u32.commas());
    assert_eq!("1000", 1000_u32.commas());
    assert_eq!("9999", 9999u32.commas());
    assert_eq!("10,000", 10000_u32.commas());
    assert_eq!("1,000,000", (1000u32 * 1000u32).commas());
    assert_eq!("1,048,576", (1024 * 1024_u32).commas());
    assert_eq!("999,000", (999 * 1000_u32).commas());
    assert_eq!("2000", (2 * 1000_u32).commas());
    assert_eq!("1,000,000,000", (1000 * 1000 * 1000_u32).commas());
    assert_eq!("4,294,967,295", std::u32::MAX.commas());

    // Test u16
    assert_eq!("0", 0u16.commas());
    assert_eq!("100", 100u16.commas());
    assert_eq!("999", 999u16.commas());
    assert_eq!("1000", 1000_u16.commas());
    assert_eq!("9999", 9999u16.commas());
    assert_eq!("10,000", 10000_u16.commas());
    assert_eq!("2000", (2 * 1000_u16).commas());
    assert_eq!("65,535", std::u16::MAX.commas());

    // Test u8
    assert_eq!("0", 0u8.commas());
    assert_eq!("1", 1u8.commas());
    assert_eq!("100", 100u8.commas());
    assert_eq!("255", std::u8::MAX.commas());

    // Test i64
    assert_eq!("0", 0i64.commas());
    assert_eq!("100", 100i64.commas());
    assert_eq!("999", 999i64.commas());
    assert_eq!("1000", 1000.commas());
    assert_eq!("9999", 9999i64.commas());
    assert_eq!("10,000", 10000_i64.commas());
    assert_eq!("1,000,000", (1000i64 * 1000i64).commas());
    assert_eq!("999,000", (999i64 * 1000i64).commas());
    assert_eq!("2000", (2 * 1000_i64).commas());
    assert_eq!("1,000,000,000", (1000 * 1000 * 1000_i64).commas());
    assert_eq!("9,223,372,036,854,775,807", std::i64::MAX.commas());
    assert_eq!("-100", (-100_i64).commas());
    assert_eq!("-999", (-999_i64).commas());
    assert_eq!("-1000", (-1000_i64).commas());
    assert_eq!("-1,000,000", (-1000 * 1000_i64).commas());
    assert_eq!("-1,048,576", (-1024 * 1024_i64).commas());
    assert_eq!("-999,000", (-999 * 1000_i64).commas());
    assert_eq!("-2000", (-2 * 1000_i64).commas());
    assert_eq!("-1,000,000,000", (-1000 * 1000 * 1000_i64).commas());
    assert_eq!("-9,223,372,036,854,775,808", (std::i64::MIN).commas());

    // Test i32.
    assert_eq!("0", 0i32.commas());
    assert_eq!("100", 100i32.commas());
    assert_eq!("999", 999i32.commas());
    assert_eq!("1000", 1000.commas());
    assert_eq!("9999", 9999i32.commas());
    assert_eq!("10,000", 10000_i32.commas());
    assert_eq!("1,000,000", (1000i32 * 1000i32).commas());
    assert_eq!("999,000", (999i32 * 1000i32).commas());
    assert_eq!("2000", (2 * 1000_i32).commas());
    assert_eq!("1,000,000,000", (1000 * 1000 * 1000_i32).commas());
    assert_eq!("2,147,483,647", std::i32::MAX.commas());
    assert_eq!("-100", (-100_i32).commas());
    assert_eq!("-999", (-999_i32).commas());
    assert_eq!("-1000", (-1000_i32).commas());
    assert_eq!("-1,000,000", (-1000 * 1000_i32).commas());
    assert_eq!("-1,048,576", (-1024 * 1024_i32).commas());
    assert_eq!("-999,000", (-999 * 1000_i32).commas());
    assert_eq!("-2000", (-2 * 1000_i32).commas());
    assert_eq!("-1,000,000,000", (-1000 * 1000 * 1000_i32).commas());
    assert_eq!("-2,147,483,648", (std::i32::MIN).commas());

    // Test i16
    assert_eq!("0", 0i16.commas());
    assert_eq!("100", 100i16.commas());
    assert_eq!("999", 999i16.commas());
    assert_eq!("1000", 1000.commas());
    assert_eq!("9999", 9999i16.commas());
    assert_eq!("10,000", 10000_i16.commas());
    assert_eq!("2000", (2 * 1000_i16).commas());
    assert_eq!("32,767", std::i16::MAX.commas());
    assert_eq!("-100", (-100_i16).commas());
    assert_eq!("-999", (-999_i16).commas());
    assert_eq!("-1000", (-1000_i16).commas());
    assert_eq!("-2000", (-2 * 1000_i16).commas());
    assert_eq!("-32,768", (std::i16::MIN).commas());

    // Test i8
    assert_eq!("0", 0i8.commas());
    assert_eq!("-1", (-1i8).commas());
    assert_eq!("100", 100i8.commas());
    assert_eq!("127", std::i8::MAX.commas());
    assert_eq!("-100", (-100_i8).commas());
    assert_eq!("-128", (std::i8::MIN).commas());
  }

  #[test]
  fn test_basic_logging() {
    let flags = LoggingEnableFlags { name: "test".to_owned(),
                                     log: false,
                                     error: false,
                                     warning: false,
                                     debug: false,
                                     info: false,
                                     modify_log: true,
                                     modify_error: true,
                                     modify_warning: true,
                                     modify_debug: true,
                                     modify_info: true };

    assert!(set_logging(&flags));
    check(&flags);

    let flags = LoggingEnableFlags { name: "test".to_owned(),
                                     log: true,
                                     error: true,
                                     warning: true,
                                     debug: true,
                                     info: true,
                                     modify_log: true,
                                     modify_error: true,
                                     modify_warning: true,
                                     modify_debug: true,
                                     modify_info: true };

    assert!(set_logging(&flags));
    check(&flags);

    // Try an arbitrary set of flags.
    let mut flags = LoggingEnableFlags { name: "test".to_owned(),
                                         log: false,
                                         error: true,
                                         warning: false,
                                         debug: true,
                                         info: false,
                                         modify_log: true,
                                         modify_error: true,
                                         modify_warning: true,
                                         modify_debug: true,
                                         modify_info: true };

    assert!(set_logging(&flags));
    check(&flags);

    // Invert the flags and try again.
    flags.log = !flags.log;
    flags.error = !flags.error;
    flags.warning = !flags.warning;
    flags.debug = !flags.debug;
    flags.info = !flags.info;

    assert!(set_logging(&flags));
    check(&flags);

    // Invert the flags and try the modify_* enablers.
    flags.log = !flags.log;
    flags.error = !flags.error;
    flags.warning = !flags.warning;
    flags.debug = !flags.debug;
    flags.info = !flags.info;

    flags.modify_log = false;
    flags.modify_error = false;
    flags.modify_warning = false;
    flags.modify_debug = false;
    flags.modify_info = false;

    // Call the flag-setting routine.
    assert!(set_logging(&flags));

    flags.log = !flags.log;
    flags.error = !flags.error;
    flags.warning = !flags.warning;
    flags.debug = !flags.debug;
    flags.info = !flags.info;

    check(&flags);

    // Check each modify_* field.

    flags.log = !flags.log;
    flags.modify_log = true;
    assert!(set_logging(&flags));
    check(&flags);

    flags.error = !flags.error;
    flags.modify_error = true;
    assert!(set_logging(&flags));
    check(&flags);

    flags.warning = !flags.warning;
    flags.modify_warning = true;
    assert!(set_logging(&flags));
    check(&flags);

    flags.debug = !flags.debug;
    flags.modify_debug = true;
    assert!(set_logging(&flags));
    check(&flags);

    flags.info = !flags.info;
    flags.modify_info = true;
    assert!(set_logging(&flags));
    check(&flags);

    // Test an invalid category.
    flags.name = "no-test".to_owned();
    assert!(!set_logging(&flags));
  }

  fn check(flags: &LoggingEnableFlags) {
    unsafe {
      for entry in &mut TABLE {
        if entry.name == flags.name {
          assert!(entry.log_enabled() == flags.log);
          assert!(entry.error_enabled() == flags.error);
          assert!(entry.warning_enabled() == flags.warning);
          assert!(entry.debug_enabled() == flags.debug);
          assert!(entry.info_enabled() == flags.info);
        }
      }
    }
  }
}