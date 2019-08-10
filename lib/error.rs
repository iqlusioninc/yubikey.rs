#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum2 {
    YKPIV_OK = 0i32,
    YKPIV_MEMORY_ERROR = -1i32,
    YKPIV_PCSC_ERROR = -2i32,
    YKPIV_SIZE_ERROR = -3i32,
    YKPIV_APPLET_ERROR = -4i32,
    YKPIV_AUTHENTICATION_ERROR = -5i32,
    YKPIV_RANDOMNESS_ERROR = -6i32,
    YKPIV_GENERIC_ERROR = -7i32,
    YKPIV_KEY_ERROR = -8i32,
    YKPIV_PARSE_ERROR = -9i32,
    YKPIV_WRONG_PIN = -10i32,
    YKPIV_INVALID_OBJECT = -11i32,
    YKPIV_ALGORITHM_ERROR = -12i32,
    YKPIV_PIN_LOCKED = -13i32,
    YKPIV_ARGUMENT_ERROR = -14i32,
    YKPIV_RANGE_ERROR = -15i32,
    YKPIV_NOT_SUPPORTED = -16i32,
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct1 {
    pub rc : Enum2,
    pub name : *const u8,
    pub description : *const u8,
}

impl Clone for Struct1 {
    fn clone(&self) -> Self { *self }
}

static mut errors
    : *const Struct1
    = Enum2::YKPIV_OK as (*const Struct1);

#[no_mangle]
pub unsafe extern fn ykpiv_strerror(mut err : Enum2) -> *const u8 {
    static mut unknown
        : *const u8
        = (*b"Unknown ykpiv error\0").as_ptr();
    let mut p : *const u8;
    if -(err as (i32)) < 0i32 || -(err as (i32)) >= ::std::mem::size_of::<*const Struct1>(
                                                    ).wrapping_div(
                                                        ::std::mem::size_of::<Struct1>()
                                                    ) as (i32) {
        unknown
    } else {
        p = (*errors.offset(-(err as (i32)) as (isize))).description;
        if p.is_null() {
            p = unknown;
        }
        p
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_strerror_name(
    mut err : Enum2
) -> *const u8 {
    if -(err as (i32)) < 0i32 || -(err as (i32)) >= ::std::mem::size_of::<*const Struct1>(
                                                    ).wrapping_div(
                                                        ::std::mem::size_of::<Struct1>()
                                                    ) as (i32) {
        0i32 as (*mut ::std::os::raw::c_void) as (*const u8)
    } else {
        (*errors.offset(-(err as (i32)) as (isize))).name
    }
}
