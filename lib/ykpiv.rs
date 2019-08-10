extern {
    fn SCardBeginTransaction(hCard : i32) -> i32;
    fn SCardConnect(
        hContext : i32,
        szReader : *const u8,
        dwShareMode : u32,
        dwPreferredProtocols : u32,
        phCard : *mut i32,
        pdwActiveProtocol : *mut u32
    ) -> i32;
    fn SCardDisconnect(hCard : i32, dwDisposition : u32) -> i32;
    fn SCardEndTransaction(hCard : i32, dwDisposition : u32) -> i32;
    fn SCardEstablishContext(
        dwScope : u32,
        pvReserved1 : *const ::std::os::raw::c_void,
        pvReserved2 : *const ::std::os::raw::c_void,
        phContext : *mut i32
    ) -> i32;
    fn SCardIsValidContext(hContext : i32) -> i32;
    fn SCardListReaders(
        hContext : i32,
        mszGroups : *const u8,
        mszReaders : *mut u8,
        pcchReaders : *mut u32
    ) -> i32;
    fn SCardReconnect(
        hCard : i32,
        dwShareMode : u32,
        dwPreferredProtocols : u32,
        dwInitialization : u32,
        pdwActiveProtocol : *mut u32
    ) -> i32;
    fn SCardReleaseContext(hContext : i32) -> i32;
    fn SCardStatus(
        hCard : i32,
        mszReaderNames : *mut u8,
        pcchReaderLen : *mut u32,
        pdwState : *mut u32,
        pdwProtocol : *mut u32,
        pbAtr : *mut u8,
        pcbAtrLen : *mut u32
    ) -> i32;
    static mut _DefaultRuneLocale : Struct1;
    fn __maskrune(arg1 : i32, arg2 : usize) -> i32;
    static mut __stderrp : *mut __sFILE;
    fn __swbuf(arg1 : i32, arg2 : *mut __sFILE) -> i32;
    fn __tolower(arg1 : i32) -> i32;
    fn __toupper(arg1 : i32) -> i32;
    fn calloc(
        __count : usize, __size : usize
    ) -> *mut ::std::os::raw::c_void;
    fn des_destroy_key(key : *mut des_key) -> Enum6;
    fn des_encrypt(
        key : *mut des_key,
        in_ : *const u8,
        inlen : usize,
        out : *mut u8,
        outlen : *mut usize
    ) -> Enum6;
    fn des_import_key(
        type_ : i32,
        keyraw : *const u8,
        keyrawlen : usize,
        key : *mut *mut des_key
    ) -> Enum6;
    fn fprintf(arg1 : *mut __sFILE, arg2 : *const u8, ...) -> i32;
    fn free(arg1 : *mut ::std::os::raw::c_void);
    fn memcmp(
        __s1 : *const ::std::os::raw::c_void,
        __s2 : *const ::std::os::raw::c_void,
        __n : usize
    ) -> i32;
    fn memcpy(
        __dst : *mut ::std::os::raw::c_void,
        __src : *const ::std::os::raw::c_void,
        __n : usize
    ) -> *mut ::std::os::raw::c_void;
    fn memmove(
        __dst : *mut ::std::os::raw::c_void,
        __src : *const ::std::os::raw::c_void,
        __len : usize
    ) -> *mut ::std::os::raw::c_void;
    fn memset(
        __b : *mut ::std::os::raw::c_void, __c : i32, __len : usize
    ) -> *mut ::std::os::raw::c_void;
    fn memset_s(
        __s : *mut ::std::os::raw::c_void,
        __smax : usize,
        __c : i32,
        __n : usize
    ) -> i32;
    fn realloc(
        __ptr : *mut ::std::os::raw::c_void, __size : usize
    ) -> *mut ::std::os::raw::c_void;
    fn snprintf(
        __str : *mut u8, __size : usize, __format : *const u8, ...
    ) -> i32;
    fn strchr(__s : *const u8, __c : i32) -> *mut u8;
    fn strlen(__s : *const u8) -> usize;
    fn strncasecmp(
        arg1 : *const u8, arg2 : *const u8, arg3 : usize
    ) -> i32;
    fn strnlen(__s1 : *const u8, __n : usize) -> usize;
    fn yk_des_is_weak_key(key : *const u8, cb_key : usize) -> bool;
    fn ykpiv_strerror(err : Enum5) -> *const u8;
}

enum __sFILEX {
}

enum des_key {
}

enum u_APDU {
}

#[derive(Copy)]
#[repr(C)]
pub struct __sbuf {
    pub _base : *mut u8,
    pub _size : i32,
}

impl Clone for __sbuf {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct __sFILE {
    pub _p : *mut u8,
    pub _r : i32,
    pub _w : i32,
    pub _flags : i16,
    pub _file : i16,
    pub _bf : __sbuf,
    pub _lbfsize : i32,
    pub _cookie : *mut ::std::os::raw::c_void,
    pub _close : unsafe extern fn(*mut ::std::os::raw::c_void) -> i32,
    pub _read : unsafe extern fn(*mut ::std::os::raw::c_void, *mut u8, i32) -> i32,
    pub _seek : unsafe extern fn(*mut ::std::os::raw::c_void, isize, i32) -> isize,
    pub _write : unsafe extern fn(*mut ::std::os::raw::c_void, *const u8, i32) -> i32,
    pub _ub : __sbuf,
    pub _extra : *mut __sFILEX,
    pub _ur : i32,
    pub _ubuf : [u8; 3],
    pub _nbuf : [u8; 1],
    pub _lb : __sbuf,
    pub _blksize : i32,
    pub _offset : isize,
}

impl Clone for __sFILE {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn __sputc(
    mut _c : i32, mut _p : *mut __sFILE
) -> i32 {
    if {
           (*_p)._w = (*_p)._w - 1;
           (*_p)._w
       } >= 0i32 || (*_p)._w >= (*_p)._lbfsize && (_c as (u8) as (i32) != b'\n' as (i32)) {
        ({
             let _rhs = _c;
             let _lhs
                 = &mut *{
                             let _old = (*_p)._p;
                             (*_p)._p = (*_p)._p.offset(1isize);
                             _old
                         };
             *_lhs = _rhs as (u8);
             *_lhs
         }) as (i32)
    } else {
        __swbuf(_c,_p)
    }
}

#[no_mangle]
pub unsafe extern fn isascii(mut _c : i32) -> i32 {
    (_c & !0x7fi32 == 0i32) as (i32)
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct3 {
    pub __min : i32,
    pub __max : i32,
    pub __map : i32,
    pub __types : *mut u32,
}

impl Clone for Struct3 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct2 {
    pub __nranges : i32,
    pub __ranges : *mut Struct3,
}

impl Clone for Struct2 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct4 {
    pub __name : [u8; 14],
    pub __mask : u32,
}

impl Clone for Struct4 {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct Struct1 {
    pub __magic : [u8; 8],
    pub __encoding : [u8; 32],
    pub __sgetrune : unsafe extern fn(*const u8, usize, *mut *const u8) -> i32,
    pub __sputrune : unsafe extern fn(i32, *mut u8, usize, *mut *mut u8) -> i32,
    pub __invalid_rune : i32,
    pub __runetype : [u32; 256],
    pub __maplower : [i32; 256],
    pub __mapupper : [i32; 256],
    pub __runetype_ext : Struct2,
    pub __maplower_ext : Struct2,
    pub __mapupper_ext : Struct2,
    pub __variable : *mut ::std::os::raw::c_void,
    pub __variable_len : i32,
    pub __ncharclasses : i32,
    pub __charclasses : *mut Struct4,
}

impl Clone for Struct1 {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn __istype(mut _c : i32, mut _f : usize) -> i32 {
    if isascii(_c) != 0 {
        !(_DefaultRuneLocale.__runetype[
              _c as (usize)
          ] as (usize) & _f == 0) as (i32)
    } else {
        !(__maskrune(_c,_f) == 0) as (i32)
    }
}

#[no_mangle]
pub unsafe extern fn __isctype(mut _c : i32, mut _f : usize) -> i32 {
    if _c < 0i32 || _c >= 256i32 {
        0i32
    } else {
        !(_DefaultRuneLocale.__runetype[
              _c as (usize)
          ] as (usize) & _f == 0) as (i32)
    }
}

#[no_mangle]
pub unsafe extern fn __wcwidth(mut _c : i32) -> i32 {
    let mut _x : u32;
    if _c == 0i32 {
        0i32
    } else {
        _x = __maskrune(_c,0xe0000000usize | 0x40000usize) as (u32);
        (if _x as (usize) & 0xe0000000usize != 0usize {
             ((_x as (usize) & 0xe0000000usize) >> 30i32) as (i32)
         } else if _x as (usize) & 0x40000usize != 0usize {
             1i32
         } else {
             -1i32
         })
    }
}

#[no_mangle]
pub unsafe extern fn isalnum(mut _c : i32) -> i32 {
    __istype(_c,(0x100isize | 0x400isize) as (usize))
}

#[no_mangle]
pub unsafe extern fn isalpha(mut _c : i32) -> i32 {
    __istype(_c,0x100usize)
}

#[no_mangle]
pub unsafe extern fn isblank(mut _c : i32) -> i32 {
    __istype(_c,0x20000usize)
}

#[no_mangle]
pub unsafe extern fn iscntrl(mut _c : i32) -> i32 {
    __istype(_c,0x200usize)
}

#[no_mangle]
pub unsafe extern fn isdigit(mut _c : i32) -> i32 {
    __isctype(_c,0x400usize)
}

#[no_mangle]
pub unsafe extern fn isgraph(mut _c : i32) -> i32 {
    __istype(_c,0x800usize)
}

#[no_mangle]
pub unsafe extern fn islower(mut _c : i32) -> i32 {
    __istype(_c,0x1000usize)
}

#[no_mangle]
pub unsafe extern fn isprint(mut _c : i32) -> i32 {
    __istype(_c,0x40000usize)
}

#[no_mangle]
pub unsafe extern fn ispunct(mut _c : i32) -> i32 {
    __istype(_c,0x2000usize)
}

#[no_mangle]
pub unsafe extern fn isspace(mut _c : i32) -> i32 {
    __istype(_c,0x4000usize)
}

#[no_mangle]
pub unsafe extern fn isupper(mut _c : i32) -> i32 {
    __istype(_c,0x8000usize)
}

#[no_mangle]
pub unsafe extern fn isxdigit(mut _c : i32) -> i32 {
    __isctype(_c,0x10000usize)
}

#[no_mangle]
pub unsafe extern fn toascii(mut _c : i32) -> i32 { _c & 0x7fi32 }

#[no_mangle]
pub unsafe extern fn tolower(mut _c : i32) -> i32 { __tolower(_c) }

#[no_mangle]
pub unsafe extern fn toupper(mut _c : i32) -> i32 { __toupper(_c) }

#[no_mangle]
pub unsafe extern fn digittoint(mut _c : i32) -> i32 {
    __maskrune(_c,0xfusize)
}

#[no_mangle]
pub unsafe extern fn ishexnumber(mut _c : i32) -> i32 {
    __istype(_c,0x10000usize)
}

#[no_mangle]
pub unsafe extern fn isideogram(mut _c : i32) -> i32 {
    __istype(_c,0x80000usize)
}

#[no_mangle]
pub unsafe extern fn isnumber(mut _c : i32) -> i32 {
    __istype(_c,0x400usize)
}

#[no_mangle]
pub unsafe extern fn isphonogram(mut _c : i32) -> i32 {
    __istype(_c,0x200000usize)
}

#[no_mangle]
pub unsafe extern fn isrune(mut _c : i32) -> i32 {
    __istype(_c,0xfffffff0usize)
}

#[no_mangle]
pub unsafe extern fn isspecial(mut _c : i32) -> i32 {
    __istype(_c,0x100000usize)
}

static mut aid : *const u8 = 0xa0i32 as (*const u8);

#[derive(Copy)]
#[repr(C)]
pub struct ykpiv_allocator {
    pub pfn_alloc : unsafe extern fn(*mut ::std::os::raw::c_void, usize) -> *mut ::std::os::raw::c_void,
    pub pfn_realloc : unsafe extern fn(*mut ::std::os::raw::c_void, *mut ::std::os::raw::c_void, usize) -> *mut ::std::os::raw::c_void,
    pub pfn_free : unsafe extern fn(*mut ::std::os::raw::c_void, *mut ::std::os::raw::c_void),
    pub alloc_data : *mut ::std::os::raw::c_void,
}

impl Clone for ykpiv_allocator {
    fn clone(&self) -> Self { *self }
}

unsafe extern fn _default_alloc(
    mut data : *mut ::std::os::raw::c_void, mut cb : usize
) -> *mut ::std::os::raw::c_void {
    data;
    calloc(cb,1usize)
}

unsafe extern fn _default_realloc(
    mut data : *mut ::std::os::raw::c_void,
    mut p : *mut ::std::os::raw::c_void,
    mut cb : usize
) -> *mut ::std::os::raw::c_void {
    data;
    realloc(p,cb)
}

unsafe extern fn _default_free(
    mut data : *mut ::std::os::raw::c_void,
    mut p : *mut ::std::os::raw::c_void
) {
    data;
    free(p);
}

#[no_mangle]
pub static mut _default_allocator
    : ykpiv_allocator
    = ykpiv_allocator {
          pfn_alloc: _default_alloc,
          pfn_realloc: _default_realloc,
          pfn_free: _default_free,
          alloc_data: 0i32 as (*mut ::std::os::raw::c_void)
      };

#[derive(Copy)]
#[repr(C)]
pub struct _ykpiv_version_t {
    pub major : u8,
    pub minor : u8,
    pub patch : u8,
}

impl Clone for _ykpiv_version_t {
    fn clone(&self) -> Self { *self }
}

#[derive(Copy)]
#[repr(C)]
pub struct ykpiv_state {
    pub context : i32,
    pub card : i32,
    pub verbose : i32,
    pub pin : *mut u8,
    pub allocator : ykpiv_allocator,
    pub isNEO : bool,
    pub ver : _ykpiv_version_t,
    pub serial : u32,
}

impl Clone for ykpiv_state {
    fn clone(&self) -> Self { *self }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_alloc(
    mut state : *mut ykpiv_state, mut size : usize
) -> *mut ::std::os::raw::c_void {
    if state.is_null() || (*state).allocator.pfn_alloc == 0 {
        0i32 as (*mut ::std::os::raw::c_void)
    } else {
        ((*state).allocator.pfn_alloc)((*state).allocator.alloc_data,size)
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_realloc(
    mut state : *mut ykpiv_state,
    mut address : *mut ::std::os::raw::c_void,
    mut size : usize
) -> *mut ::std::os::raw::c_void {
    if state.is_null() || (*state).allocator.pfn_realloc == 0 {
        0i32 as (*mut ::std::os::raw::c_void)
    } else {
        ((*state).allocator.pfn_realloc)(
            (*state).allocator.alloc_data,
            address,
            size
        )
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_free(
    mut state : *mut ykpiv_state,
    mut data : *mut ::std::os::raw::c_void
) { if data.is_null() || state.is_null(
                         ) || (*state).allocator.pfn_free == 0 {
    } else {
        ((*state).allocator.pfn_free)((*state).allocator.alloc_data,data);
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_set_length(
    mut buffer : *mut u8, mut length : usize
) -> u32 {
    if length < 0x80usize {
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = length as (u8);
        1u32
    } else if length < 0x100usize {
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = 0x81u8;
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = length as (u8);
        2u32
    } else {
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = 0x82u8;
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = (length >> 8i32 & 0xffusize) as (u8);
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = (length as (u8) as (i32) & 0xffi32) as (u8);
        3u32
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_get_length(
    mut buffer : *const u8, mut len : *mut usize
) -> u32 {
    if *buffer.offset(0isize) as (i32) < 0x81i32 {
        *len = *buffer.offset(0isize) as (usize);
        1u32
    } else if *buffer as (i32) & 0x7fi32 == 1i32 {
        *len = *buffer.offset(1isize) as (usize);
        2u32
    } else if *buffer as (i32) & 0x7fi32 == 2i32 {
        let mut tmp : usize = *buffer.offset(1isize) as (usize);
        *len = (tmp << 8i32).wrapping_add(
                   *buffer.offset(2isize) as (usize)
               );
        3u32
    } else {
        0u32
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_has_valid_length(
    mut buffer : *const u8, mut len : usize
) -> bool {
    if *buffer.offset(0isize) as (i32) < 0x81i32 && (len > 0usize) {
        true
    } else if *buffer as (i32) & 0x7fi32 == 1i32 && (len > 1usize) {
        true
    } else if *buffer as (i32) & 0x7fi32 == 2i32 && (len > 2usize) {
        true
    } else {
        false
    }
}

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum5 {
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

#[no_mangle]
pub unsafe extern fn ykpiv_init_with_allocator(
    mut state : *mut *mut ykpiv_state,
    mut verbose : i32,
    mut allocator : *const ykpiv_allocator
) -> Enum5 {
    let mut s : *mut ykpiv_state;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut *mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if 0i32 as (*mut ::std::os::raw::c_void) as (*const ykpiv_allocator) == allocator || (*allocator).pfn_alloc == 0 || (*allocator).pfn_realloc == 0 || (*allocator).pfn_free == 0 {
        Enum5::YKPIV_MEMORY_ERROR
    } else {
        s = ((*allocator).pfn_alloc)(
                (*allocator).alloc_data,
                ::std::mem::size_of::<ykpiv_state>()
            ) as (*mut ykpiv_state);
        (if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == s {
             Enum5::YKPIV_MEMORY_ERROR
         } else {
             memset(
                 s as (*mut ::std::os::raw::c_void),
                 0i32,
                 ::std::mem::size_of::<ykpiv_state>()
             );
             (*s).pin = 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8);
             (*s).allocator = *allocator;
             (*s).verbose = verbose;
             (*s).context = -1i32;
             *state = s;
             Enum5::YKPIV_OK
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_init(
    mut state : *mut *mut ykpiv_state, mut verbose : i32
) -> Enum5 {
    ykpiv_init_with_allocator(
        state,
        verbose,
        &mut _default_allocator as (*mut ykpiv_allocator) as (*const ykpiv_allocator)
    )
}

unsafe extern fn _ykpiv_done(
    mut state : *mut ykpiv_state, mut disconnect : bool
) -> Enum5 {
    if disconnect {
        ykpiv_disconnect(state);
    }
    _cache_pin(
        state,
        0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
        0usize
    );
    _ykpiv_free(state,state as (*mut ::std::os::raw::c_void));
    Enum5::YKPIV_OK
}

#[no_mangle]
pub unsafe extern fn ykpiv_done_with_external_card(
    mut state : *mut ykpiv_state
) -> Enum5 {
    _ykpiv_done(state,false)
}

#[no_mangle]
pub unsafe extern fn ykpiv_done(
    mut state : *mut ykpiv_state
) -> Enum5 {
    _ykpiv_done(state,true)
}

#[no_mangle]
pub unsafe extern fn ykpiv_disconnect(
    mut state : *mut ykpiv_state
) -> Enum5 {
    if (*state).card != 0 {
        SCardDisconnect((*state).card,0x1u32);
        (*state).card = 0i32;
    }
    if SCardIsValidContext((*state).context) == 0x0i32 {
        SCardReleaseContext((*state).context);
        (*state).context = -1i32;
    }
    Enum5::YKPIV_OK
}

#[no_mangle]
pub unsafe extern fn _ykpiv_select_application(
    mut state : *mut ykpiv_state
) -> Enum5 {
    let mut apdu : u_APDU;
    let mut data : [u8; 255];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 255]>() as (u32);
    let mut sw : i32;
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if {
           res = _send_data(
                     state,
                     &mut apdu as (*mut u_APDU),
                     data.as_mut_ptr(),
                     &mut recv_len as (*mut u32),
                     &mut sw as (*mut i32)
                 );
           res
       } as (i32) != Enum5::YKPIV_OK as (i32) {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                ykpiv_strerror(res)
            );
        }
        res
    } else if sw != 0x9000i32 {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Failed selecting application: %04x\n\0").as_ptr(),
                sw
            );
        }
        Enum5::YKPIV_GENERIC_ERROR
    } else {
        res = _ykpiv_get_version(
                  state,
                  0i32 as (*mut ::std::os::raw::c_void) as (*mut _ykpiv_version_t)
              );
        if res as (i32) != Enum5::YKPIV_OK as (i32) {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"Failed to retrieve version: \'%s\'\n\0").as_ptr(),
                    ykpiv_strerror(res)
                );
            }
        }
        res = _ykpiv_get_serial(
                  state,
                  0i32 as (*mut ::std::os::raw::c_void) as (*mut u32),
                  false
              );
        if res as (i32) != Enum5::YKPIV_OK as (i32) {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"Failed to retrieve serial number: \'%s\'\n\0").as_ptr(),
                    ykpiv_strerror(res)
                );
            }
            res = Enum5::YKPIV_OK;
        }
        res
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_ensure_application_selected(
    mut state : *mut ykpiv_state
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    state;
    res
}

unsafe extern fn _ykpiv_connect(
    mut state : *mut ykpiv_state, mut context : usize, mut card : usize
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if context != (*state).context as (usize) && (0x0i32 != SCardIsValidContext(
                                                                       context as (i32)
                                                                   )) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if card != (*state).card as (usize) {
            let mut reader : [u8; 3072];
            let mut reader_len
                : u32
                = ::std::mem::size_of::<[u8; 3072]>() as (u32);
            let mut atr : [u8; 33];
            let mut atr_len : u32 = ::std::mem::size_of::<[u8; 33]>() as (u32);
            if 0x0i32 != SCardStatus(
                             card as (i32),
                             reader.as_mut_ptr(),
                             &mut reader_len as (*mut u32),
                             0i32 as (*mut ::std::os::raw::c_void) as (*mut u32),
                             0i32 as (*mut ::std::os::raw::c_void) as (*mut u32),
                             atr.as_mut_ptr(),
                             &mut atr_len as (*mut u32)
                         ) {
                return Enum5::YKPIV_PCSC_ERROR;
            } else {
                (*state).isNEO = ::std::mem::size_of::<[u8; 23]>().wrapping_sub(
                                     1usize
                                 ) == atr_len as (usize) && (0i32 == memcmp(
                                                                         (*b";\xFC\x13\0\0\x811\xFE\x15YubikeyNEOr3\xE1\0").as_ptr(
                                                                         ) as (*const ::std::os::raw::c_void),
                                                                         atr.as_mut_ptr(
                                                                         ) as (*const ::std::os::raw::c_void),
                                                                         atr_len as (usize)
                                                                     ));
            }
        }
        (*state).context = context as (i32);
        (*state).card = card as (i32);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_connect_with_external_card(
    mut state : *mut ykpiv_state, mut context : usize, mut card : usize
) -> Enum5 {
    _ykpiv_connect(state,context,card)
}

#[no_mangle]
pub unsafe extern fn ykpiv_connect(
    mut state : *mut ykpiv_state, mut wanted : *const u8
) -> Enum5 {
    let mut _currentBlock;
    let mut active_protocol : u32;
    let mut reader_buf : [u8; 2048];
    let mut num_readers : usize = ::std::mem::size_of::<[u8; 2048]>();
    let mut rc : isize;
    let mut reader_ptr : *mut u8;
    let mut card : i32 = -1i32;
    let mut ret
        : Enum5
        = ykpiv_list_readers(
              state,
              reader_buf.as_mut_ptr(),
              &mut num_readers as (*mut usize)
          );
    if ret as (i32) != Enum5::YKPIV_OK as (i32) {
        ret
    } else {
        reader_ptr = reader_buf.as_mut_ptr();
        'loop2: loop {
            if !(*reader_ptr as (i32) != b'\0' as (i32)) {
                _currentBlock = 3;
                break;
            }
            if !wanted.is_null() {
                let mut ptr : *mut u8 = reader_ptr;
                let mut found : bool = false;
                'loop10: loop {
                    if strlen(ptr as (*const u8)) < strlen(wanted) {
                        _currentBlock = 14;
                        break;
                    }
                    if strncasecmp(ptr as (*const u8),wanted,strlen(wanted)) == 0i32 {
                        _currentBlock = 13;
                        break;
                    }
                    if *{
                            let _old = ptr;
                            ptr = ptr.offset(1isize);
                            _old
                        } == 0 {
                        _currentBlock = 14;
                        break;
                    }
                }
                if _currentBlock == 13 {
                    found = true;
                }
                if found as (i32) == 0i32 {
                    if (*state).verbose != 0 {
                        fprintf(
                            __stderrp,
                            (*b"skipping reader \'%s\' since it doesn\'t match \'%s\'.\n\0").as_ptr(
                            ),
                            reader_ptr,
                            wanted
                        );
                        _currentBlock = 26;
                    } else {
                        _currentBlock = 26;
                    }
                } else {
                    _currentBlock = 15;
                }
            } else {
                _currentBlock = 15;
            }
            if _currentBlock == 15 {
                if (*state).verbose != 0 {
                    fprintf(
                        __stderrp,
                        (*b"trying to connect to reader \'%s\'.\n\0").as_ptr(),
                        reader_ptr
                    );
                }
                rc = SCardConnect(
                         (*state).context,
                         reader_ptr as (*const u8),
                         0x2u32,
                         0x2u32,
                         &mut card as (*mut i32),
                         &mut active_protocol as (*mut u32)
                     ) as (isize);
                if rc != 0x0isize {
                    if (*state).verbose != 0 {
                        fprintf(
                            __stderrp,
                            (*b"SCardConnect failed, rc=%08lx\n\0").as_ptr(),
                            rc
                        );
                    }
                } else if Enum5::YKPIV_OK as (i32) == _ykpiv_connect(
                                                          state,
                                                          (*state).context as (usize),
                                                          card as (usize)
                                                      ) as (i32) {
                    _currentBlock = 19;
                    break;
                }
            }
            reader_ptr = reader_ptr.offset(
                             strlen(reader_ptr as (*const u8)).wrapping_add(1usize) as (isize)
                         );
        }
        (if _currentBlock == 3 {
             (if *reader_ptr as (i32) == b'\0' as (i32) {
                  if (*state).verbose != 0 {
                      fprintf(
                          __stderrp,
                          (*b"error: no usable reader found.\n\0").as_ptr()
                      );
                  }
                  SCardReleaseContext((*state).context);
                  (*state).context = -1i32;
                  Enum5::YKPIV_PCSC_ERROR
              } else {
                  Enum5::YKPIV_GENERIC_ERROR
              })
         } else if Enum5::YKPIV_OK as (i32) != {
                                                   ret = _ykpiv_begin_transaction(state);
                                                   ret
                                               } as (i32) {
             Enum5::YKPIV_PCSC_ERROR
         } else {
             ret = _ykpiv_select_application(state);
             _ykpiv_end_transaction(state);
             ret
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_list_readers(
    mut state : *mut ykpiv_state,
    mut readers : *mut u8,
    mut len : *mut usize
) -> Enum5 {
    let mut num_readers : u32 = 0u32;
    let mut rc : isize;
    if SCardIsValidContext((*state).context) != 0x0i32 {
        rc = SCardEstablishContext(
                 0x2u32,
                 0i32 as (*mut ::std::os::raw::c_void) as (*const ::std::os::raw::c_void),
                 0i32 as (*mut ::std::os::raw::c_void) as (*const ::std::os::raw::c_void),
                 &mut (*state).context as (*mut i32)
             ) as (isize);
        if rc != 0x0isize {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"error: SCardEstablishContext failed, rc=%08lx\n\0").as_ptr(),
                    rc
                );
            }
            return Enum5::YKPIV_PCSC_ERROR;
        }
    }
    rc = SCardListReaders(
             (*state).context,
             0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
             0i32 as (*mut ::std::os::raw::c_void) as (*mut u8),
             &mut num_readers as (*mut u32)
         ) as (isize);
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"error: SCardListReaders failed, rc=%08lx\n\0").as_ptr(),
                rc
            );
        }
        SCardReleaseContext((*state).context);
        (*state).context = -1i32;
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if num_readers as (usize) > *len {
            num_readers = *len as (u32);
        } else if num_readers as (usize) < *len {
            *len = num_readers as (usize);
        }
        rc = SCardListReaders(
                 (*state).context,
                 0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
                 readers,
                 &mut num_readers as (*mut u32)
             ) as (isize);
        (if rc != 0x0isize {
             if (*state).verbose != 0 {
                 fprintf(
                     __stderrp,
                     (*b"error: SCardListReaders failed, rc=%08lx\n\0").as_ptr(),
                     rc
                 );
             }
             SCardReleaseContext((*state).context);
             (*state).context = -1i32;
             Enum5::YKPIV_PCSC_ERROR
         } else {
             *len = num_readers as (usize);
             Enum5::YKPIV_OK
         })
    }
}

unsafe extern fn reconnect(mut state : *mut ykpiv_state) -> Enum5 {
    let mut active_protocol : u32 = 0u32;
    let mut rc : isize;
    let mut res : Enum5;
    let mut tries : i32;
    if (*state).verbose != 0 {
        fprintf(
            __stderrp,
            (*b"trying to reconnect to current reader.\n\0").as_ptr()
        );
    }
    rc = SCardReconnect(
             (*state).card,
             0x2u32,
             0x2u32,
             0x1u32,
             &mut active_protocol as (*mut u32)
         ) as (isize);
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"SCardReconnect failed, rc=%08lx\n\0").as_ptr(),
                rc
            );
        }
        Enum5::YKPIV_PCSC_ERROR
    } else if {
                  res = _ykpiv_select_application(state);
                  res
              } as (i32) != Enum5::YKPIV_OK as (i32) {
        res
    } else if !(*state).pin.is_null() {
        ykpiv_verify(
            state,
            (*state).pin as (*const u8),
            &mut tries as (*mut i32)
        )
    } else {
        Enum5::YKPIV_OK
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_begin_transaction(
    mut state : *mut ykpiv_state
) -> Enum5 {
    let mut rc : isize;
    rc = SCardBeginTransaction((*state).card) as (isize);
    if (rc as (usize) & 0xffffffffusize) as (isize) as (usize) == 0x80100068usize {
        let mut res : Enum5 = Enum5::YKPIV_OK;
        if {
               res = reconnect(state);
               res
           } as (i32) != Enum5::YKPIV_OK as (i32) {
            return res;
        } else {
            rc = SCardBeginTransaction((*state).card) as (isize);
        }
    }
    if rc != 0x0isize {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"error: Failed to begin pcsc transaction, rc=%08lx\n\0").as_ptr(
                ),
                rc
            );
        }
        Enum5::YKPIV_PCSC_ERROR
    } else {
        Enum5::YKPIV_OK
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_end_transaction(
    mut state : *mut ykpiv_state
) -> Enum5 {
    let mut rc
        : isize
        = SCardEndTransaction((*state).card,0x0u32) as (isize);
    if rc != 0x0isize && ((*state).verbose != 0) {
        fprintf(
            __stderrp,
            (*b"error: Failed to end pcsc transaction, rc=%08lx\n\0").as_ptr(),
            rc
        );
        Enum5::YKPIV_PCSC_ERROR
    } else {
        Enum5::YKPIV_OK
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_transfer_data(
    mut state : *mut ykpiv_state,
    mut templ : *const u8,
    mut in_data : *const u8,
    mut in_len : isize,
    mut out_data : *mut u8,
    mut out_len : *mut usize,
    mut sw : *mut i32
) -> Enum5 {
    let mut _currentBlock;
    let mut in_ptr : *const u8 = in_data;
    let mut max_out : usize = *out_len;
    let mut res : Enum5;
    *out_len = 0usize;
    'loop1: loop {
        let mut this_size : usize = 0xffusize;
        let mut data : [u8; 261];
        let mut recv_len
            : u32
            = ::std::mem::size_of::<[u8; 261]>() as (u32);
        let mut apdu : u_APDU;
        if (*state).verbose > 2i32 {
            fprintf(
                __stderrp,
                (*b"Going to send %lu bytes in this go.\n\0").as_ptr(),
                this_size
            );
        }
        res = _send_data(
                  state,
                  &mut apdu as (*mut u_APDU),
                  data.as_mut_ptr(),
                  &mut recv_len as (*mut u32),
                  sw
              );
        if res as (i32) != Enum5::YKPIV_OK as (i32) {
            _currentBlock = 24;
            break;
        }
        if *sw != 0x9000i32 && (*sw >> 8i32 != 0x61i32) {
            _currentBlock = 24;
            break;
        }
        if (*out_len).wrapping_add(recv_len as (usize)).wrapping_sub(
               2usize
           ) > max_out {
            _currentBlock = 21;
            break;
        }
        if !out_data.is_null() {
            memcpy(
                out_data as (*mut ::std::os::raw::c_void),
                data.as_mut_ptr() as (*const ::std::os::raw::c_void),
                recv_len.wrapping_sub(2u32) as (usize)
            );
            out_data = out_data.offset(recv_len.wrapping_sub(2u32) as (isize));
            *out_len = (*out_len).wrapping_add(
                           recv_len.wrapping_sub(2u32) as (usize)
                       );
        }
        in_ptr = in_ptr.offset(this_size as (isize));
        if !(in_ptr < in_data.offset(in_len)) {
            _currentBlock = 10;
            break;
        }
    }
    if _currentBlock == 10 {
        'loop10: loop {
            if !(*sw >> 8i32 == 0x61i32) {
                _currentBlock = 24;
                break;
            }
            let mut apdu : u_APDU;
            let mut data : [u8; 261];
            let mut recv_len
                : u32
                = ::std::mem::size_of::<[u8; 261]>() as (u32);
            if (*state).verbose > 2i32 {
                fprintf(
                    __stderrp,
                    (*b"The card indicates there is %d bytes more data for us.\n\0").as_ptr(
                    ),
                    *sw & 0xffi32
                );
            }
            res = _send_data(
                      state,
                      &mut apdu as (*mut u_APDU),
                      data.as_mut_ptr(),
                      &mut recv_len as (*mut u32),
                      sw
                  );
            if res as (i32) != Enum5::YKPIV_OK as (i32) {
                _currentBlock = 24;
                break;
            }
            if *sw != 0x9000i32 && (*sw >> 8i32 != 0x61i32) {
                _currentBlock = 24;
                break;
            }
            if (*out_len).wrapping_add(recv_len as (usize)).wrapping_sub(
                   2usize
               ) > max_out {
                _currentBlock = 18;
                break;
            }
            if out_data.is_null() {
                continue;
            }
            memcpy(
                out_data as (*mut ::std::os::raw::c_void),
                data.as_mut_ptr() as (*const ::std::os::raw::c_void),
                recv_len.wrapping_sub(2u32) as (usize)
            );
            out_data = out_data.offset(recv_len.wrapping_sub(2u32) as (isize));
            *out_len = (*out_len).wrapping_add(
                           recv_len.wrapping_sub(2u32) as (usize)
                       );
        }
        if _currentBlock == 24 {
        } else {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"Output buffer to small, wanted to write %lu, max was %lu.\0").as_ptr(
                    ),
                    (*out_len).wrapping_add(recv_len as (usize)).wrapping_sub(2usize),
                    max_out
                );
            }
            res = Enum5::YKPIV_SIZE_ERROR;
        }
    } else if _currentBlock == 21 {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Output buffer to small, wanted to write %lu, max was %lu.\n\0").as_ptr(
                ),
                (*out_len).wrapping_add(recv_len as (usize)).wrapping_sub(2usize),
                max_out
            );
        }
        res = Enum5::YKPIV_SIZE_ERROR;
    }
    res
}

#[no_mangle]
pub unsafe extern fn ykpiv_transfer_data(
    mut state : *mut ykpiv_state,
    mut templ : *const u8,
    mut in_data : *const u8,
    mut in_len : isize,
    mut out_data : *mut u8,
    mut out_len : *mut usize,
    mut sw : *mut i32
) -> Enum5 {
    let mut res : Enum5;
    if {
           res = _ykpiv_begin_transaction(state);
           res
       } as (i32) != Enum5::YKPIV_OK as (i32) {
        *out_len = 0usize;
        Enum5::YKPIV_PCSC_ERROR
    } else {
        res = _ykpiv_transfer_data(
                  state,
                  templ,
                  in_data,
                  in_len,
                  out_data,
                  out_len,
                  sw
              );
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe extern fn dump_hex(mut buf : *const u8, mut len : u32) {
    let mut i : u32;
    i = 0u32;
    'loop1: loop {
        if !(i < len) {
            break;
        }
        fprintf(
            __stderrp,
            (*b"%02x \0").as_ptr(),
            *buf.offset(i as (isize)) as (i32)
        );
        i = i.wrapping_add(1u32);
    }
}

#[no_mangle]
pub unsafe extern fn _send_data(
    mut state : *mut ykpiv_state,
    mut apdu : *mut u_APDU,
    mut data : *mut u8,
    mut recv_len : *mut u32,
    mut sw : *mut i32
) -> Enum5 {
    let mut rc : isize;
    let mut send_len : u32 = 0u32;
    let mut tmp_len : u32 = *recv_len;
    *recv_len = tmp_len;
    if (*state).verbose > 1i32 {
        fprintf(__stderrp,(*b"< \0").as_ptr());
        dump_hex(data as (*const u8),*recv_len);
        fprintf(__stderrp,(*b"\n\0").as_ptr());
    }
    if *recv_len >= 2u32 {
        *sw = *data.offset(
                   (*recv_len).wrapping_sub(2u32) as (isize)
               ) as (i32) << 8i32 | *data.offset(
                                         (*recv_len).wrapping_sub(1u32) as (isize)
                                     ) as (i32);
    } else {
        *sw = 0i32;
    }
    Enum5::YKPIV_OK
}

#[derive(Clone, Copy)]
#[repr(i32)]
pub enum Enum6 {
    DES_OK = 0i32,
    DES_INVALID_PARAMETER = -1i32,
    DES_BUFFER_TOO_SMALL = -2i32,
    DES_MEMORY_ERROR = -3i32,
    DES_GENERAL_ERROR = -4i32,
}

#[no_mangle]
pub unsafe extern fn ykpiv_authenticate(
    mut state : *mut ykpiv_state, mut key : *const u8
) -> Enum5 {
    let mut apdu : u_APDU;
    let mut data : [u8; 261];
    let mut challenge : [u8; 8];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32;
    let mut res : Enum5;
    let mut drc : Enum6 = Enum6::DES_OK;
    let mut mgm_key
        : *mut des_key
        = 0i32 as (*mut ::std::os::raw::c_void) as (*mut des_key);
    let mut out_len : usize = 0usize;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if Enum5::YKPIV_OK as (i32) != {
                                              res = _ykpiv_begin_transaction(state);
                                              res
                                          } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            if 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) == key {
                key = (*b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\0").as_ptr(
                      );
            }
            if Enum6::DES_OK as (i32) != des_import_key(
                                             1i32,
                                             key,
                                             (8i32 * 3i32) as (usize),
                                             &mut mgm_key as (*mut *mut des_key)
                                         ) as (i32) {
                res = Enum5::YKPIV_ALGORITHM_ERROR;
            } else {
                let mut response : [u8; 8];
                out_len = ::std::mem::size_of::<[u8; 8]>();
                drc = des_encrypt(
                          mgm_key,
                          challenge.as_mut_ptr() as (*const u8),
                          ::std::mem::size_of::<[u8; 8]>(),
                          response.as_mut_ptr(),
                          &mut out_len as (*mut usize)
                      );
                if drc as (i32) != Enum6::DES_OK as (i32) {
                    res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                } else if memcmp(
                              response.as_mut_ptr() as (*const ::std::os::raw::c_void),
                              data.as_mut_ptr().offset(
                                  4isize
                              ) as (*const ::std::os::raw::c_void),
                              8usize
                          ) == 0i32 {
                    res = Enum5::YKPIV_OK;
                } else {
                    res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                }
            }
        }
        if !mgm_key.is_null() {
            des_destroy_key(mgm_key);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_set_mgmkey(
    mut state : *mut ykpiv_state, mut new_key : *const u8
) -> Enum5 {
    ykpiv_set_mgmkey2(state,new_key,0u8)
}

#[no_mangle]
pub unsafe extern fn ykpiv_set_mgmkey2(
    mut state : *mut ykpiv_state, mut new_key : *const u8, touch : u8
) -> Enum5 {
    let mut apdu : u_APDU;
    let mut data : [u8; 261];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32;
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            if yk_des_is_weak_key(new_key,(8i32 * 3i32) as (usize)) {
                if (*state).verbose != 0 {
                    fprintf(__stderrp,(*b"Won\'t set new key \'\0").as_ptr());
                    dump_hex(new_key,(8i32 * 3i32) as (u32));
                    fprintf(
                        __stderrp,
                        (*b"\' since it\'s weak (with odd parity).\n\0").as_ptr()
                    );
                }
                res = Enum5::YKPIV_KEY_ERROR;
            } else if !({
                            res = _send_data(
                                      state,
                                      &mut apdu as (*mut u_APDU),
                                      data.as_mut_ptr(),
                                      &mut recv_len as (*mut u32),
                                      &mut sw as (*mut i32)
                                  );
                            res
                        } as (i32) != Enum5::YKPIV_OK as (i32)) {
                if !(sw == 0x9000i32) {
                    res = Enum5::YKPIV_GENERIC_ERROR;
                }
            }
        }
        memset_s(
            &mut apdu as (*mut u_APDU) as (*mut ::std::os::raw::c_void),
            ::std::mem::size_of::<u_APDU>(),
            0i32,
            ::std::mem::size_of::<u_APDU>()
        );
        _ykpiv_end_transaction(state);
        res
    }
}

static mut hex_translate
    : *mut u8
    = (*b"0123456789abcdef\0").as_ptr() as (*mut u8);

#[no_mangle]
pub unsafe extern fn ykpiv_hex_decode(
    mut hex_in : *const u8,
    mut in_len : usize,
    mut hex_out : *mut u8,
    mut out_len : *mut usize
) -> Enum5 {
    let mut _currentBlock;
    let mut i : usize;
    let mut first : bool = true;
    if *out_len < in_len.wrapping_div(2usize) {
        Enum5::YKPIV_SIZE_ERROR
    } else if in_len.wrapping_rem(2usize) != 0usize {
        Enum5::YKPIV_SIZE_ERROR
    } else {
        *out_len = in_len.wrapping_div(2usize);
        i = 0usize;
        'loop3: loop {
            if !(i < in_len) {
                _currentBlock = 4;
                break;
            }
            let mut ind_ptr
                : *mut u8
                = strchr(
                      hex_translate as (*const u8),
                      tolower(
                          *{
                               let _old = hex_in;
                               hex_in = hex_in.offset(1isize);
                               _old
                           } as (i32)
                      )
                  );
            let mut index : i32 = 0i32;
            if ind_ptr.is_null() {
                _currentBlock = 6;
                break;
            }
            index = ((ind_ptr as (isize)).wrapping_sub(
                         hex_translate as (isize)
                     ) / ::std::mem::size_of::<u8>() as (isize)) as (i32);
            if first {
                *hex_out = (index << 4i32) as (u8);
            } else {
                let _rhs = index;
                let _lhs
                    = &mut *{
                                let _old = hex_out;
                                hex_out = hex_out.offset(1isize);
                                _old
                            };
                *_lhs = (*_lhs as (i32) | _rhs) as (u8);
            }
            first = !first;
            i = i.wrapping_add(1usize);
        }
        (if _currentBlock == 4 {
             Enum5::YKPIV_OK
         } else {
             Enum5::YKPIV_PARSE_ERROR
         })
    }
}

unsafe extern fn _general_authenticate(
    mut state : *mut ykpiv_state,
    mut sign_in : *const u8,
    mut in_len : usize,
    mut out : *mut u8,
    mut out_len : *mut usize,
    mut algorithm : u8,
    mut key : u8,
    mut decipher : bool
) -> Enum5 {
    let mut _currentBlock;
    let mut indata : [u8; 1024];
    let mut dataptr : *mut u8 = indata.as_mut_ptr();
    let mut data : [u8; 1024];
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut recv_len : usize = ::std::mem::size_of::<[u8; 1024]>();
    let mut key_len : usize = 0usize;
    let mut sw : i32 = 0i32;
    let mut bytes : usize;
    let mut len : usize = 0usize;
    let mut res : Enum5;
    if algorithm as (i32) == 0x14i32 {
        _currentBlock = 12;
    } else if algorithm as (i32) == 0x11i32 {
        key_len = 32usize;
        _currentBlock = 12;
    } else {
        if !(algorithm as (i32) == 0x7i32) {
            if algorithm as (i32) == 0x6i32 {
                key_len = 128usize;
            } else {
                return Enum5::YKPIV_ALGORITHM_ERROR;
            }
        }
        if key_len == 0usize {
            key_len = 256usize;
        }
        if in_len != key_len {
            return Enum5::YKPIV_SIZE_ERROR;
        } else {
            _currentBlock = 16;
        }
    }
    if _currentBlock == 12 {
        if key_len == 0usize {
            key_len = 48usize;
        }
        if !decipher && (in_len > key_len) {
            return Enum5::YKPIV_SIZE_ERROR;
        } else if decipher && (in_len != key_len.wrapping_mul(
                                             2usize
                                         ).wrapping_add(
                                             1usize
                                         )) {
            return Enum5::YKPIV_SIZE_ERROR;
        }
    }
    if in_len < 0x80usize {
        bytes = 1usize;
    } else if in_len < 0xffusize {
        bytes = 2usize;
    } else {
        bytes = 3usize;
    }
    *{
         let _old = dataptr;
         dataptr = dataptr.offset(1isize);
         _old
     } = 0x7cu8;
    dataptr = dataptr.offset(
                  _ykpiv_set_length(
                      dataptr,
                      in_len.wrapping_add(bytes).wrapping_add(3usize)
                  ) as (isize)
              );
    *{
         let _old = dataptr;
         dataptr = dataptr.offset(1isize);
         _old
     } = 0x82u8;
    *{
         let _old = dataptr;
         dataptr = dataptr.offset(1isize);
         _old
     } = 0x0u8;
    *{
         let _old = dataptr;
         dataptr = dataptr.offset(1isize);
         _old
     } = if (algorithm as (i32) == 0x11i32 || algorithm as (i32) == 0x14i32) && decipher {
             0x85i32
         } else {
             0x81i32
         } as (u8);
    dataptr = dataptr.offset(
                  _ykpiv_set_length(dataptr,in_len) as (isize)
              );
    memcpy(
        dataptr as (*mut ::std::os::raw::c_void),
        sign_in as (*const ::std::os::raw::c_void),
        in_len
    );
    dataptr = dataptr.offset(in_len as (isize));
    if {
           res = ykpiv_transfer_data(
                     state,
                     templ as (*const u8),
                     indata.as_mut_ptr() as (*const u8),
                     (dataptr as (isize)).wrapping_sub(
                         indata.as_mut_ptr() as (isize)
                     ) / ::std::mem::size_of::<u8>() as (isize),
                     data.as_mut_ptr(),
                     &mut recv_len as (*mut usize),
                     &mut sw as (*mut i32)
                 );
           res
       } as (i32) != Enum5::YKPIV_OK as (i32) {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Sign command failed to communicate.\n\0").as_ptr()
            );
        }
        res
    } else if sw != 0x9000i32 {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Failed sign command with code %x.\n\0").as_ptr(),
                sw
            );
        }
        (if sw == 0x6982i32 {
             Enum5::YKPIV_AUTHENTICATION_ERROR
         } else {
             Enum5::YKPIV_GENERIC_ERROR
         })
    } else if data[0usize] as (i32) != 0x7ci32 {
        if (*state).verbose != 0 {
            fprintf(
                __stderrp,
                (*b"Failed parsing signature reply.\n\0").as_ptr()
            );
        }
        Enum5::YKPIV_PARSE_ERROR
    } else {
        dataptr = data.as_mut_ptr().offset(1isize);
        dataptr = dataptr.offset(
                      _ykpiv_get_length(
                          dataptr as (*const u8),
                          &mut len as (*mut usize)
                      ) as (isize)
                  );
        (if *dataptr as (i32) != 0x82i32 {
             if (*state).verbose != 0 {
                 fprintf(
                     __stderrp,
                     (*b"Failed parsing signature reply.\n\0").as_ptr()
                 );
             }
             Enum5::YKPIV_PARSE_ERROR
         } else {
             dataptr = dataptr.offset(1isize);
             dataptr = dataptr.offset(
                           _ykpiv_get_length(
                               dataptr as (*const u8),
                               &mut len as (*mut usize)
                           ) as (isize)
                       );
             (if len > *out_len {
                  if (*state).verbose != 0 {
                      fprintf(__stderrp,(*b"Wrong size on output buffer.\n\0").as_ptr());
                  }
                  Enum5::YKPIV_SIZE_ERROR
              } else {
                  *out_len = len;
                  memcpy(
                      out as (*mut ::std::os::raw::c_void),
                      dataptr as (*const ::std::os::raw::c_void),
                      len
                  );
                  Enum5::YKPIV_OK
              })
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_sign_data(
    mut state : *mut ykpiv_state,
    mut raw_in : *const u8,
    mut in_len : usize,
    mut sign_out : *mut u8,
    mut out_len : *mut usize,
    mut algorithm : u8,
    mut key : u8
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if Enum5::YKPIV_OK as (i32) != {
                                              res = _ykpiv_begin_transaction(state);
                                              res
                                          } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        res = _general_authenticate(
                  state,
                  raw_in,
                  in_len,
                  sign_out,
                  out_len,
                  algorithm,
                  key,
                  false
              );
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_decipher_data(
    mut state : *mut ykpiv_state,
    mut in_ : *const u8,
    mut in_len : usize,
    mut out : *mut u8,
    mut out_len : *mut usize,
    mut algorithm : u8,
    mut key : u8
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if Enum5::YKPIV_OK as (i32) != {
                                              res = _ykpiv_begin_transaction(state);
                                              res
                                          } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        res = _general_authenticate(
                  state,
                  in_,
                  in_len,
                  out,
                  out_len,
                  algorithm,
                  key,
                  true
              );
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe extern fn _ykpiv_get_version(
    mut state : *mut ykpiv_state, mut p_version : *mut _ykpiv_version_t
) -> Enum5 {
    let mut apdu : u_APDU;
    let mut data : [u8; 261];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32;
    let mut res : Enum5;
    if state.is_null() {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else if (*state).ver.major != 0 || (*state).ver.minor != 0 || (*state).ver.patch != 0 {
        if !p_version.is_null() {
            memcpy(
                p_version as (*mut ::std::os::raw::c_void),
                &mut (*state).ver as (*mut _ykpiv_version_t) as (*const ::std::os::raw::c_void),
                ::std::mem::size_of::<_ykpiv_version_t>()
            );
        }
        Enum5::YKPIV_OK
    } else if {
                  res = _send_data(
                            state,
                            &mut apdu as (*mut u_APDU),
                            data.as_mut_ptr(),
                            &mut recv_len as (*mut u32),
                            &mut sw as (*mut i32)
                        );
                  res
              } as (i32) != Enum5::YKPIV_OK as (i32) {
        res
    } else {
        if sw == 0x9000i32 {
            if recv_len < 3u32 {
                return Enum5::YKPIV_SIZE_ERROR;
            } else {
                (*state).ver.major = data[0usize];
                (*state).ver.minor = data[1usize];
                (*state).ver.patch = data[2usize];
                if !p_version.is_null() {
                    memcpy(
                        p_version as (*mut ::std::os::raw::c_void),
                        &mut (*state).ver as (*mut _ykpiv_version_t) as (*const ::std::os::raw::c_void),
                        ::std::mem::size_of::<_ykpiv_version_t>()
                    );
                }
            }
        } else {
            res = Enum5::YKPIV_GENERIC_ERROR;
        }
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_get_version(
    mut state : *mut ykpiv_state,
    mut version : *mut u8,
    mut len : usize
) -> Enum5 {
    let mut res : Enum5;
    let mut result : i32 = 0i32;
    let mut ver
        : _ykpiv_version_t
        = _ykpiv_version_t { major: 0u8, minor: 0u8, patch: 0u8 };
    if {
           res = _ykpiv_begin_transaction(state);
           res
       } as (i32) < Enum5::YKPIV_OK as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !({
                 res = _ykpiv_ensure_application_selected(state);
                 res
             } as (i32) < Enum5::YKPIV_OK as (i32)) {
            if {
                   res = _ykpiv_get_version(
                             state,
                             &mut ver as (*mut _ykpiv_version_t)
                         );
                   res
               } as (i32) >= Enum5::YKPIV_OK as (i32) {
                result = snprintf(
                             version,
                             len,
                             (*b"%d.%d.%d\0").as_ptr(),
                             ver.major as (i32),
                             ver.minor as (i32),
                             ver.patch as (i32)
                         );
                if result < 0i32 {
                    res = Enum5::YKPIV_SIZE_ERROR;
                }
            }
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe extern fn _ykpiv_get_serial(
    mut state : *mut ykpiv_state,
    mut p_serial : *mut u32,
    mut f_force : bool
) -> Enum5 {
    let mut _currentBlock;
    let mut res : Enum5 = Enum5::YKPIV_OK;
    let mut apdu : u_APDU;
    let mut yk_applet : *const u8 = 0xa0i32 as (*const u8);
    let mut data : [u8; 255];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 255]>() as (u32);
    let mut sw : i32;
    let mut p_temp
        : *mut u8
        = 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8);
    if state.is_null() {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else if !f_force && ((*state).serial != 0u32) {
        if !p_serial.is_null() {
            *p_serial = (*state).serial;
        }
        Enum5::YKPIV_OK
    } else {
        if (*state).ver.major as (i32) < 5i32 {
            let mut temp : [u8; 255];
            recv_len = ::std::mem::size_of::<[u8; 255]>() as (u32);
            if {
                   res = _send_data(
                             state,
                             &mut apdu as (*mut u_APDU),
                             temp.as_mut_ptr(),
                             &mut recv_len as (*mut u32),
                             &mut sw as (*mut i32)
                         );
                   res
               } as (i32) < Enum5::YKPIV_OK as (i32) {
                if (*state).verbose != 0 {
                    fprintf(
                        __stderrp,
                        (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                        ykpiv_strerror(res)
                    );
                    _currentBlock = 37;
                } else {
                    _currentBlock = 37;
                }
            } else if sw != 0x9000i32 {
                if (*state).verbose != 0 {
                    fprintf(
                        __stderrp,
                        (*b"Failed selecting yk application: %04x\n\0").as_ptr(),
                        sw
                    );
                }
                res = Enum5::YKPIV_GENERIC_ERROR;
                _currentBlock = 37;
            } else {
                recv_len = ::std::mem::size_of::<[u8; 255]>() as (u32);
                if {
                       res = _send_data(
                                 state,
                                 &mut apdu as (*mut u_APDU),
                                 data.as_mut_ptr(),
                                 &mut recv_len as (*mut u32),
                                 &mut sw as (*mut i32)
                             );
                       res
                   } as (i32) < Enum5::YKPIV_OK as (i32) {
                    if (*state).verbose != 0 {
                        fprintf(
                            __stderrp,
                            (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                            ykpiv_strerror(res)
                        );
                        _currentBlock = 37;
                    } else {
                        _currentBlock = 37;
                    }
                } else if sw != 0x9000i32 {
                    if (*state).verbose != 0 {
                        fprintf(
                            __stderrp,
                            (*b"Failed retrieving serial number: %04x\n\0").as_ptr(),
                            sw
                        );
                    }
                    res = Enum5::YKPIV_GENERIC_ERROR;
                    _currentBlock = 37;
                } else {
                    recv_len = ::std::mem::size_of::<[u8; 255]>() as (u32);
                    if {
                           res = _send_data(
                                     state,
                                     &mut apdu as (*mut u_APDU),
                                     temp.as_mut_ptr(),
                                     &mut recv_len as (*mut u32),
                                     &mut sw as (*mut i32)
                                 );
                           res
                       } as (i32) < Enum5::YKPIV_OK as (i32) {
                        if (*state).verbose != 0 {
                            fprintf(
                                __stderrp,
                                (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                                ykpiv_strerror(res)
                            );
                        }
                        return res;
                    } else if sw != 0x9000i32 {
                        if (*state).verbose != 0 {
                            fprintf(
                                __stderrp,
                                (*b"Failed selecting application: %04x\n\0").as_ptr(),
                                sw
                            );
                        }
                        return Enum5::YKPIV_GENERIC_ERROR;
                    }
                    _currentBlock = 17;
                }
            }
        } else {
            if {
                   res = _send_data(
                             state,
                             &mut apdu as (*mut u_APDU),
                             data.as_mut_ptr(),
                             &mut recv_len as (*mut u32),
                             &mut sw as (*mut i32)
                         );
                   res
               } as (i32) != Enum5::YKPIV_OK as (i32) {
                if (*state).verbose != 0 {
                    fprintf(
                        __stderrp,
                        (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                        ykpiv_strerror(res)
                    );
                }
                return res;
            } else if sw != 0x9000i32 {
                if (*state).verbose != 0 {
                    fprintf(
                        __stderrp,
                        (*b"Failed retrieving serial number: %04x\n\0").as_ptr(),
                        sw
                    );
                }
                return Enum5::YKPIV_GENERIC_ERROR;
            }
            _currentBlock = 17;
        }
        if _currentBlock == 17 {
            if recv_len < 4u32 {
                return Enum5::YKPIV_SIZE_ERROR;
            } else {
                p_temp = &mut (*state).serial as (*mut u32) as (*mut u8);
                *{
                     let _old = p_temp;
                     p_temp = p_temp.offset(1isize);
                     _old
                 } = data[3usize];
                *{
                     let _old = p_temp;
                     p_temp = p_temp.offset(1isize);
                     _old
                 } = data[2usize];
                *{
                     let _old = p_temp;
                     p_temp = p_temp.offset(1isize);
                     _old
                 } = data[1usize];
                *{
                     let _old = p_temp;
                     p_temp = p_temp.offset(1isize);
                     _old
                 } = data[0usize];
                if !p_serial.is_null() {
                    *p_serial = (*state).serial;
                }
            }
        }
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_get_serial(
    mut state : *mut ykpiv_state, mut p_serial : *mut u32
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if {
           res = _ykpiv_begin_transaction(state);
           res
       } as (i32) != Enum5::YKPIV_OK as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !({
                 res = _ykpiv_ensure_application_selected(state);
                 res
             } as (i32) != Enum5::YKPIV_OK as (i32)) {
            res = _ykpiv_get_serial(state,p_serial,false);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe extern fn _cache_pin(
    mut state : *mut ykpiv_state, mut pin : *const u8, mut len : usize
) -> Enum5 {
    if state.is_null() {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else if !pin.is_null() && ((*state).pin as (*const u8) == pin) {
        Enum5::YKPIV_OK
    } else {
        if !(*state).pin.is_null() {
            memset_s(
                (*state).pin as (*mut ::std::os::raw::c_void),
                strnlen((*state).pin as (*const u8),8usize),
                0i32,
                strnlen((*state).pin as (*const u8),8usize)
            );
            _ykpiv_free(state,(*state).pin as (*mut ::std::os::raw::c_void));
            (*state).pin = 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8);
        }
        if !pin.is_null() && (len > 0usize) {
            (*state).pin = _ykpiv_alloc(
                               state,
                               len.wrapping_mul(::std::mem::size_of::<u8>()).wrapping_add(1usize)
                           ) as (*mut u8);
            if (*state).pin == 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) {
                return Enum5::YKPIV_MEMORY_ERROR;
            } else {
                memcpy(
                    (*state).pin as (*mut ::std::os::raw::c_void),
                    pin as (*const ::std::os::raw::c_void),
                    len
                );
                *(*state).pin.offset(len as (isize)) = 0u8;
            }
        }
        Enum5::YKPIV_OK
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_verify(
    mut state : *mut ykpiv_state,
    mut pin : *const u8,
    mut tries : *mut i32
) -> Enum5 {
    ykpiv_verify_select(
        state,
        pin,
        if !pin.is_null() { strlen(pin) } else { 0usize },
        tries,
        false
    )
}

unsafe extern fn _verify(
    mut state : *mut ykpiv_state,
    mut pin : *const u8,
    pin_len : usize,
    mut tries : *mut i32
) -> Enum5 {
    let mut apdu : u_APDU;
    let mut data : [u8; 261];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32;
    let mut res : Enum5;
    if pin_len > 8usize {
        Enum5::YKPIV_SIZE_ERROR
    } else {
        res = _send_data(
                  state,
                  &mut apdu as (*mut u_APDU),
                  data.as_mut_ptr(),
                  &mut recv_len as (*mut u32),
                  &mut sw as (*mut i32)
              );
        memset_s(
            &mut apdu as (*mut u_APDU) as (*mut ::std::os::raw::c_void),
            ::std::mem::size_of::<u_APDU>(),
            0i32,
            ::std::mem::size_of::<u_APDU>()
        );
        (if res as (i32) != Enum5::YKPIV_OK as (i32) {
             res
         } else if sw == 0x9000i32 {
             if !pin.is_null() && (pin_len != 0) {
                 _cache_pin(state,pin,pin_len);
             }
             if !tries.is_null() {
                 *tries = sw & 0xfi32;
             }
             Enum5::YKPIV_OK
         } else if sw >> 8i32 == 0x63i32 {
             if !tries.is_null() {
                 *tries = sw & 0xfi32;
             }
             Enum5::YKPIV_WRONG_PIN
         } else if sw == 0x6983i32 {
             if !tries.is_null() {
                 *tries = 0i32;
             }
             Enum5::YKPIV_WRONG_PIN
         } else {
             Enum5::YKPIV_GENERIC_ERROR
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_verify_select(
    mut state : *mut ykpiv_state,
    mut pin : *const u8,
    pin_len : usize,
    mut tries : *mut i32,
    mut force_select : bool
) -> Enum5 {
    let mut _currentBlock;
    let mut res : Enum5 = Enum5::YKPIV_OK;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if force_select {
            if Enum5::YKPIV_OK as (i32) != {
                                               res = _ykpiv_ensure_application_selected(state);
                                               res
                                           } as (i32) {
                _currentBlock = 4;
            } else {
                _currentBlock = 3;
            }
        } else {
            _currentBlock = 3;
        }
        if _currentBlock == 3 {
            res = _verify(state,pin,pin_len,tries);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_get_pin_retries(
    mut state : *mut ykpiv_state, mut tries : *mut i32
) -> Enum5 {
    let mut res : Enum5;
    let mut ykrc : Enum5;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state || 0i32 as (*mut ::std::os::raw::c_void) as (*mut i32) == tries {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else {
        res = _ykpiv_select_application(state);
        (if res as (i32) != Enum5::YKPIV_OK as (i32) {
             res
         } else {
             ykrc = ykpiv_verify(
                        state,
                        0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
                        tries
                    );
             (if ykrc as (i32) == Enum5::YKPIV_WRONG_PIN as (i32) {
                  Enum5::YKPIV_OK as (i32)
              } else {
                  ykrc as (i32)
              }) as (Enum5)
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_set_pin_retries(
    mut state : *mut ykpiv_state,
    mut pin_tries : i32,
    mut puk_tries : i32
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut data : [u8; 255];
    let mut recv_len : usize = ::std::mem::size_of::<[u8; 255]>();
    let mut sw : i32 = 0i32;
    if pin_tries == 0i32 || puk_tries == 0i32 {
        Enum5::YKPIV_OK
    } else if pin_tries > 0xffi32 || puk_tries > 0xffi32 || pin_tries < 1i32 || puk_tries < 1i32 {
        Enum5::YKPIV_RANGE_ERROR
    } else {
        *templ.offset(2isize) = pin_tries as (u8);
        *templ.offset(3isize) = puk_tries as (u8);
        (if Enum5::YKPIV_OK as (i32) != {
                                            res = _ykpiv_begin_transaction(state);
                                            res
                                        } as (i32) {
             Enum5::YKPIV_PCSC_ERROR
         } else {
             if !(Enum5::YKPIV_OK as (i32) != {
                                                  res = _ykpiv_ensure_application_selected(state);
                                                  res
                                              } as (i32)) {
                 res = ykpiv_transfer_data(
                           state,
                           templ as (*const u8),
                           0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
                           0isize,
                           data.as_mut_ptr(),
                           &mut recv_len as (*mut usize),
                           &mut sw as (*mut i32)
                       );
                 if Enum5::YKPIV_OK as (i32) == res as (i32) {
                     if !(0x9000i32 == sw) {
                         if sw == 0x6983i32 {
                             res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                         } else if sw == 0x6982i32 {
                             res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                         } else {
                             res = Enum5::YKPIV_GENERIC_ERROR;
                         }
                     }
                 }
             }
             _ykpiv_end_transaction(state);
             res
         })
    }
}

unsafe extern fn _ykpiv_change_pin(
    mut state : *mut ykpiv_state,
    mut action : i32,
    mut current_pin : *const u8,
    mut current_pin_len : usize,
    mut new_pin : *const u8,
    mut new_pin_len : usize,
    mut tries : *mut i32
) -> Enum5 {
    let mut sw : i32;
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut indata : [u8; 16];
    let mut data : [u8; 255];
    let mut recv_len : usize = ::std::mem::size_of::<[u8; 255]>();
    let mut res : Enum5;
    if current_pin_len > 8usize {
        Enum5::YKPIV_SIZE_ERROR
    } else if new_pin_len > 8usize {
        Enum5::YKPIV_SIZE_ERROR
    } else {
        if action == 1i32 {
            *templ.offset(1isize) = 0x2cu8;
        } else if action == 2i32 {
            *templ.offset(3isize) = 0x81u8;
        }
        memcpy(
            indata.as_mut_ptr() as (*mut ::std::os::raw::c_void),
            current_pin as (*const ::std::os::raw::c_void),
            current_pin_len
        );
        if current_pin_len < 8usize {
            memset(
                indata.as_mut_ptr().offset(
                    current_pin_len as (isize)
                ) as (*mut ::std::os::raw::c_void),
                0xffi32,
                8usize.wrapping_sub(current_pin_len)
            );
        }
        memcpy(
            indata.as_mut_ptr().offset(
                8isize
            ) as (*mut ::std::os::raw::c_void),
            new_pin as (*const ::std::os::raw::c_void),
            new_pin_len
        );
        if new_pin_len < 8usize {
            memset(
                indata.as_mut_ptr().offset(8isize).offset(
                    new_pin_len as (isize)
                ) as (*mut ::std::os::raw::c_void),
                0xffi32,
                8usize.wrapping_sub(new_pin_len)
            );
        }
        res = ykpiv_transfer_data(
                  state,
                  templ as (*const u8),
                  indata.as_mut_ptr() as (*const u8),
                  ::std::mem::size_of::<[u8; 16]>() as (isize),
                  data.as_mut_ptr(),
                  &mut recv_len as (*mut usize),
                  &mut sw as (*mut i32)
              );
        memset_s(
            indata.as_mut_ptr() as (*mut ::std::os::raw::c_void),
            ::std::mem::size_of::<[u8; 16]>(),
            0i32,
            ::std::mem::size_of::<[u8; 16]>()
        );
        (if res as (i32) != Enum5::YKPIV_OK as (i32) {
             res
         } else if sw != 0x9000i32 {
             (if sw >> 8i32 == 0x63i32 {
                  if !tries.is_null() {
                      *tries = sw & 0xfi32;
                  }
                  Enum5::YKPIV_WRONG_PIN
              } else if sw == 0x6983i32 {
                  Enum5::YKPIV_PIN_LOCKED
              } else {
                  if (*state).verbose != 0 {
                      fprintf(
                          __stderrp,
                          (*b"Failed changing pin, token response code: %x.\n\0").as_ptr(),
                          sw
                      );
                  }
                  Enum5::YKPIV_GENERIC_ERROR
              })
         } else {
             Enum5::YKPIV_OK
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_change_pin(
    mut state : *mut ykpiv_state,
    mut current_pin : *const u8,
    mut current_pin_len : usize,
    mut new_pin : *const u8,
    mut new_pin_len : usize,
    mut tries : *mut i32
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_GENERIC_ERROR;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            res = _ykpiv_change_pin(
                      state,
                      0i32,
                      current_pin,
                      current_pin_len,
                      new_pin,
                      new_pin_len,
                      tries
                  );
            if res as (i32) == Enum5::YKPIV_OK as (i32) && (new_pin != 0i32 as (*mut ::std::os::raw::c_void) as (*const u8)) {
                _cache_pin(state,new_pin,new_pin_len);
            }
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_change_puk(
    mut state : *mut ykpiv_state,
    mut current_puk : *const u8,
    mut current_puk_len : usize,
    mut new_puk : *const u8,
    mut new_puk_len : usize,
    mut tries : *mut i32
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_GENERIC_ERROR;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            res = _ykpiv_change_pin(
                      state,
                      2i32,
                      current_puk,
                      current_puk_len,
                      new_puk,
                      new_puk_len,
                      tries
                  );
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_unblock_pin(
    mut state : *mut ykpiv_state,
    mut puk : *const u8,
    mut puk_len : usize,
    mut new_pin : *const u8,
    mut new_pin_len : usize,
    mut tries : *mut i32
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_GENERIC_ERROR;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            res = _ykpiv_change_pin(
                      state,
                      1i32,
                      puk,
                      puk_len,
                      new_pin,
                      new_pin_len,
                      tries
                  );
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_fetch_object(
    mut state : *mut ykpiv_state,
    mut object_id : i32,
    mut data : *mut u8,
    mut len : *mut usize
) -> Enum5 {
    let mut res : Enum5;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            res = _ykpiv_fetch_object(state,object_id,data,len);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

unsafe extern fn set_object(
    mut object_id : i32, mut buffer : *mut u8
) -> *mut u8 {
    *{
         let _old = buffer;
         buffer = buffer.offset(1isize);
         _old
     } = 0x5cu8;
    if object_id == 0x7ei32 {
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = 1u8;
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = 0x7eu8;
    } else if object_id > 0xffffi32 && (object_id <= 0xffffffi32) {
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = 3u8;
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = (object_id >> 16i32 & 0xffi32) as (u8);
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = (object_id >> 8i32 & 0xffi32) as (u8);
        *{
             let _old = buffer;
             buffer = buffer.offset(1isize);
             _old
         } = (object_id & 0xffi32) as (u8);
    }
    buffer
}

#[no_mangle]
pub unsafe extern fn _ykpiv_fetch_object(
    mut state : *mut ykpiv_state,
    mut object_id : i32,
    mut data : *mut u8,
    mut len : *mut usize
) -> Enum5 {
    let mut sw : i32;
    let mut indata : [u8; 5];
    let mut inptr : *mut u8 = indata.as_mut_ptr();
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut res : Enum5;
    inptr = set_object(object_id,inptr);
    if inptr == 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) {
        Enum5::YKPIV_INVALID_OBJECT
    } else if {
                  res = ykpiv_transfer_data(
                            state,
                            templ as (*const u8),
                            indata.as_mut_ptr() as (*const u8),
                            (inptr as (isize)).wrapping_sub(
                                indata.as_mut_ptr() as (isize)
                            ) / ::std::mem::size_of::<u8>() as (isize),
                            data,
                            len,
                            &mut sw as (*mut i32)
                        );
                  res
              } as (i32) != Enum5::YKPIV_OK as (i32) {
        res
    } else if sw == 0x9000i32 {
        let mut outlen : usize = 0usize;
        let mut offs : u32 = 0u32;
        (if *len < 2usize || !_ykpiv_has_valid_length(
                                  data.offset(1isize) as (*const u8),
                                  (*len).wrapping_sub(1usize)
                              ) {
             Enum5::YKPIV_SIZE_ERROR
         } else {
             offs = _ykpiv_get_length(
                        data.offset(1isize) as (*const u8),
                        &mut outlen as (*mut usize)
                    );
             (if offs == 0u32 {
                  Enum5::YKPIV_SIZE_ERROR
              } else if outlen.wrapping_add(offs as (usize)).wrapping_add(
                            1usize
                        ) != *len {
                  if (*state).verbose != 0 {
                      fprintf(
                          __stderrp,
                          (*b"Invalid length indicated in object, total objlen is %lu, indicated length is %lu.\0").as_ptr(
                          ),
                          *len,
                          outlen
                      );
                  }
                  Enum5::YKPIV_SIZE_ERROR
              } else {
                  memmove(
                      data as (*mut ::std::os::raw::c_void),
                      data.offset(1isize).offset(
                          offs as (isize)
                      ) as (*const ::std::os::raw::c_void),
                      outlen
                  );
                  *len = outlen;
                  Enum5::YKPIV_OK
              })
         })
    } else {
        Enum5::YKPIV_GENERIC_ERROR
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_save_object(
    mut state : *mut ykpiv_state,
    mut object_id : i32,
    mut indata : *mut u8,
    mut len : usize
) -> Enum5 {
    let mut res : Enum5;
    if Enum5::YKPIV_OK as (i32) != {
                                       res = _ykpiv_begin_transaction(state);
                                       res
                                   } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            res = _ykpiv_save_object(state,object_id,indata,len);
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn _ykpiv_save_object(
    mut state : *mut ykpiv_state,
    mut object_id : i32,
    mut indata : *mut u8,
    mut len : usize
) -> Enum5 {
    let mut data : [u8; 3072];
    let mut dataptr : *mut u8 = data.as_mut_ptr();
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut sw : i32;
    let mut res : Enum5;
    let mut outlen : usize = 0usize;
    if len > ::std::mem::size_of::<[u8; 3072]>().wrapping_sub(9usize) {
        Enum5::YKPIV_SIZE_ERROR
    } else {
        dataptr = set_object(object_id,dataptr);
        (if dataptr == 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) {
             Enum5::YKPIV_INVALID_OBJECT
         } else {
             *{
                  let _old = dataptr;
                  dataptr = dataptr.offset(1isize);
                  _old
              } = 0x53u8;
             dataptr = dataptr.offset(
                           _ykpiv_set_length(dataptr,len) as (isize)
                       );
             memcpy(
                 dataptr as (*mut ::std::os::raw::c_void),
                 indata as (*const ::std::os::raw::c_void),
                 len
             );
             dataptr = dataptr.offset(len as (isize));
             (if {
                     res = _ykpiv_transfer_data(
                               state,
                               templ as (*const u8),
                               data.as_mut_ptr() as (*const u8),
                               (dataptr as (isize)).wrapping_sub(
                                   data.as_mut_ptr() as (isize)
                               ) / ::std::mem::size_of::<u8>() as (isize),
                               0i32 as (*mut ::std::os::raw::c_void) as (*mut u8),
                               &mut outlen as (*mut usize),
                               &mut sw as (*mut i32)
                           );
                     res
                 } as (i32) != Enum5::YKPIV_OK as (i32) {
                  res
              } else if 0x9000i32 == sw {
                  Enum5::YKPIV_OK
              } else if 0x6982i32 == sw {
                  Enum5::YKPIV_AUTHENTICATION_ERROR
              } else {
                  Enum5::YKPIV_GENERIC_ERROR
              })
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_import_private_key(
    mut state : *mut ykpiv_state,
    key : u8,
    mut algorithm : u8,
    mut p : *const u8,
    mut p_len : usize,
    mut q : *const u8,
    mut q_len : usize,
    mut dp : *const u8,
    mut dp_len : usize,
    mut dq : *const u8,
    mut dq_len : usize,
    mut qinv : *const u8,
    mut qinv_len : usize,
    mut ec_data : *const u8,
    mut ec_data_len : u8,
    pin_policy : u8,
    touch_policy : u8
) -> Enum5 {
    let mut _currentBlock;
    let mut key_data : [u8; 1024];
    let mut in_ptr : *mut u8 = key_data.as_mut_ptr();
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut data : [u8; 256];
    let mut recv_len : usize = ::std::mem::size_of::<[u8; 256]>();
    let mut elem_len : u32;
    let mut sw : i32;
    let mut params : [*const u8; 5];
    let mut lens : [usize; 5];
    let mut padding : usize;
    let mut n_params : u8;
    let mut i : i32;
    let mut param_tag : i32;
    let mut res : Enum5;
    if state == 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) {
        Enum5::YKPIV_GENERIC_ERROR
    } else if key as (i32) == 0x9bi32 || key as (i32) < 0x82i32 || key as (i32) > 0x95i32 && (key as (i32) < 0x9ai32) || key as (i32) > 0x9ei32 && (key as (i32) != 0xf9i32) {
        Enum5::YKPIV_KEY_ERROR
    } else if pin_policy as (i32) != 0i32 && (pin_policy as (i32) != 1i32) && (pin_policy as (i32) != 2i32) && (pin_policy as (i32) != 3i32) {
        Enum5::YKPIV_GENERIC_ERROR
    } else if touch_policy as (i32) != 0i32 && (touch_policy as (i32) != 1i32) && (touch_policy as (i32) != 2i32) && (touch_policy as (i32) != 3i32) {
        Enum5::YKPIV_GENERIC_ERROR
    } else {
        if algorithm as (i32) == 0x6i32 || algorithm as (i32) == 0x7i32 {
            if p_len.wrapping_add(q_len).wrapping_add(dp_len).wrapping_add(
                   dq_len
               ).wrapping_add(
                   qinv_len
               ) >= ::std::mem::size_of::<[u8; 1024]>() {
                return Enum5::YKPIV_SIZE_ERROR;
            } else {
                if algorithm as (i32) == 0x6i32 {
                    elem_len = 64u32;
                }
                if algorithm as (i32) == 0x7i32 {
                    elem_len = 128u32;
                }
                if p == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) || q == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) || dp == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) || dq == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) || qinv == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) {
                    return Enum5::YKPIV_GENERIC_ERROR;
                } else {
                    params[0usize] = p;
                    lens[0usize] = p_len;
                    params[1usize] = q;
                    lens[1usize] = q_len;
                    params[2usize] = dp;
                    lens[2usize] = dp_len;
                    params[3usize] = dq;
                    lens[3usize] = dq_len;
                    params[4usize] = qinv;
                    lens[4usize] = qinv_len;
                    param_tag = 0x1i32;
                    n_params = 5u8;
                }
            }
        } else if algorithm as (i32) == 0x11i32 || algorithm as (i32) == 0x14i32 {
            if ec_data_len as (usize) >= ::std::mem::size_of::<[u8; 1024]>() {
                return Enum5::YKPIV_SIZE_ERROR;
            } else {
                if algorithm as (i32) == 0x11i32 {
                    elem_len = 32u32;
                }
                if algorithm as (i32) == 0x14i32 {
                    elem_len = 48u32;
                }
                if ec_data == 0i32 as (*mut ::std::os::raw::c_void) as (*const u8) {
                    return Enum5::YKPIV_GENERIC_ERROR;
                } else {
                    params[0usize] = ec_data;
                    lens[0usize] = ec_data_len as (usize);
                    param_tag = 0x6i32;
                    n_params = 1u8;
                }
            }
        } else {
            return Enum5::YKPIV_ALGORITHM_ERROR;
        }
        i = 0i32;
        'loop24: loop {
            if !(i < n_params as (i32)) {
                _currentBlock = 25;
                break;
            }
            let mut remaining : usize;
            *{
                 let _old = in_ptr;
                 in_ptr = in_ptr.offset(1isize);
                 _old
             } = (param_tag + i) as (u8);
            in_ptr = in_ptr.offset(
                         _ykpiv_set_length(in_ptr,elem_len as (usize)) as (isize)
                     );
            padding = (elem_len as (usize)).wrapping_sub(lens[i as (usize)]);
            remaining = (key_data.as_mut_ptr() as (usize)).wrapping_add(
                            ::std::mem::size_of::<[u8; 1024]>()
                        ).wrapping_sub(
                            in_ptr as (usize)
                        );
            if padding > remaining {
                _currentBlock = 39;
                break;
            }
            memset(in_ptr as (*mut ::std::os::raw::c_void),0i32,padding);
            in_ptr = in_ptr.offset(padding as (isize));
            memcpy(
                in_ptr as (*mut ::std::os::raw::c_void),
                params[i as (usize)] as (*const ::std::os::raw::c_void),
                lens[i as (usize)]
            );
            in_ptr = in_ptr.offset(lens[i as (usize)] as (isize));
            i = i + 1;
        }
        if _currentBlock == 25 {
            if pin_policy as (i32) != 0i32 {
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = 0xaau8;
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = 0x1u8;
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = pin_policy;
            }
            if touch_policy as (i32) != 0i32 {
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = 0xabu8;
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = 0x1u8;
                *{
                     let _old = in_ptr;
                     in_ptr = in_ptr.offset(1isize);
                     _old
                 } = touch_policy;
            }
            if Enum5::YKPIV_OK as (i32) != {
                                               res = _ykpiv_begin_transaction(state);
                                               res
                                           } as (i32) {
                return Enum5::YKPIV_PCSC_ERROR;
            } else if !(Enum5::YKPIV_OK as (i32) != {
                                                        res = _ykpiv_ensure_application_selected(
                                                                  state
                                                              );
                                                        res
                                                    } as (i32)) {
                if !({
                         res = ykpiv_transfer_data(
                                   state,
                                   templ as (*const u8),
                                   key_data.as_mut_ptr() as (*const u8),
                                   (in_ptr as (isize)).wrapping_sub(
                                       key_data.as_mut_ptr() as (isize)
                                   ) / ::std::mem::size_of::<u8>() as (isize),
                                   data.as_mut_ptr(),
                                   &mut recv_len as (*mut usize),
                                   &mut sw as (*mut i32)
                               );
                         res
                     } as (i32) != Enum5::YKPIV_OK as (i32)) {
                    if 0x9000i32 != sw {
                        res = Enum5::YKPIV_GENERIC_ERROR;
                        if sw == 0x6982i32 {
                            res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                        }
                    }
                }
            }
        } else {
            res = Enum5::YKPIV_ALGORITHM_ERROR;
        }
        memset_s(
            key_data.as_mut_ptr() as (*mut ::std::os::raw::c_void),
            ::std::mem::size_of::<[u8; 1024]>(),
            0i32,
            ::std::mem::size_of::<[u8; 1024]>()
        );
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_attest(
    mut state : *mut ykpiv_state,
    key : u8,
    mut data : *mut u8,
    mut data_len : *mut usize
) -> Enum5 {
    let mut res : Enum5;
    let mut templ : *mut u8 = 0i32 as (*mut u8);
    let mut sw : i32;
    let mut ul_data_len : usize;
    if state == 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) || data == 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) || data_len == 0i32 as (*mut ::std::os::raw::c_void) as (*mut usize) {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else {
        ul_data_len = *data_len;
        (if Enum5::YKPIV_OK as (i32) != {
                                            res = _ykpiv_begin_transaction(state);
                                            res
                                        } as (i32) {
             Enum5::YKPIV_PCSC_ERROR
         } else {
             if !(Enum5::YKPIV_OK as (i32) != {
                                                  res = _ykpiv_ensure_application_selected(state);
                                                  res
                                              } as (i32)) {
                 if !({
                          res = ykpiv_transfer_data(
                                    state,
                                    templ as (*const u8),
                                    0i32 as (*mut ::std::os::raw::c_void) as (*const u8),
                                    0isize,
                                    data,
                                    &mut ul_data_len as (*mut usize),
                                    &mut sw as (*mut i32)
                                );
                          res
                      } as (i32) != Enum5::YKPIV_OK as (i32)) {
                     if 0x9000i32 != sw {
                         res = Enum5::YKPIV_GENERIC_ERROR;
                         if 0x6d00i32 == sw {
                             res = Enum5::YKPIV_NOT_SUPPORTED;
                         }
                     } else if *data.offset(0isize) as (i32) != 0x30i32 {
                         res = Enum5::YKPIV_GENERIC_ERROR;
                     } else {
                         *data_len = ul_data_len;
                     }
                 }
             }
             _ykpiv_end_transaction(state);
             res
         })
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_auth_getchallenge(
    mut state : *mut ykpiv_state,
    mut challenge : *mut u8,
    challenge_len : usize
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    let mut apdu : u_APDU = 0i32 as (u_APDU);
    let mut data : [u8; 261];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32 = 0i32;
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) == challenge {
        Enum5::YKPIV_GENERIC_ERROR
    } else if 8usize != challenge_len {
        Enum5::YKPIV_SIZE_ERROR
    } else if Enum5::YKPIV_OK as (i32) != {
                                              res = _ykpiv_begin_transaction(state);
                                              res
                                          } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        if !(Enum5::YKPIV_OK as (i32) != {
                                             res = _ykpiv_ensure_application_selected(state);
                                             res
                                         } as (i32)) {
            if !({
                     res = _send_data(
                               state,
                               &mut apdu as (*mut u_APDU),
                               data.as_mut_ptr(),
                               &mut recv_len as (*mut u32),
                               &mut sw as (*mut i32)
                           );
                     res
                 } as (i32) != Enum5::YKPIV_OK as (i32)) {
                if sw != 0x9000i32 {
                    res = Enum5::YKPIV_AUTHENTICATION_ERROR;
                } else {
                    memcpy(
                        challenge as (*mut ::std::os::raw::c_void),
                        data.as_mut_ptr().offset(
                            4isize
                        ) as (*const ::std::os::raw::c_void),
                        8usize
                    );
                }
            }
        }
        _ykpiv_end_transaction(state);
        res
    }
}

#[no_mangle]
pub unsafe extern fn ykpiv_auth_verifyresponse(
    mut state : *mut ykpiv_state,
    mut response : *mut u8,
    response_len : usize
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    let mut apdu : u_APDU = 0i32 as (u_APDU);
    let mut data : [u8; 261];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 261]>() as (u32);
    let mut sw : i32 = 0i32;
    let mut dataptr : *mut u8 = 0i32 as (*mut u8);
    if 0i32 as (*mut ::std::os::raw::c_void) as (*mut ykpiv_state) == state {
        Enum5::YKPIV_GENERIC_ERROR
    } else if 0i32 as (*mut ::std::os::raw::c_void) as (*mut u8) == response {
        Enum5::YKPIV_GENERIC_ERROR
    } else if 8usize != response_len {
        Enum5::YKPIV_SIZE_ERROR
    } else if Enum5::YKPIV_OK as (i32) != {
                                              res = _ykpiv_begin_transaction(state);
                                              res
                                          } as (i32) {
        Enum5::YKPIV_PCSC_ERROR
    } else {
        recv_len = ::std::mem::size_of::<[u8; 261]>() as (u32);
        *{
             let _old = dataptr;
             dataptr = dataptr.offset(1isize);
             _old
         } = 0x7cu8;
        *{
             let _old = dataptr;
             dataptr = dataptr.offset(1isize);
             _old
         } = 0xau8;
        *{
             let _old = dataptr;
             dataptr = dataptr.offset(1isize);
             _old
         } = 0x82u8;
        *{
             let _old = dataptr;
             dataptr = dataptr.offset(1isize);
             _old
         } = 8u8;
        memcpy(
            dataptr as (*mut ::std::os::raw::c_void),
            response as (*const ::std::os::raw::c_void),
            response_len
        );
        dataptr = dataptr.offset(8isize);
        if !({
                 res = _send_data(
                           state,
                           &mut apdu as (*mut u_APDU),
                           data.as_mut_ptr(),
                           &mut recv_len as (*mut u32),
                           &mut sw as (*mut i32)
                       );
                 res
             } as (i32) != Enum5::YKPIV_OK as (i32)) {
            if sw != 0x9000i32 {
                res = Enum5::YKPIV_AUTHENTICATION_ERROR;
            }
        }
        memset_s(
            &mut apdu as (*mut u_APDU) as (*mut ::std::os::raw::c_void),
            ::std::mem::size_of::<u_APDU>(),
            0i32,
            ::std::mem::size_of::<u_APDU>()
        );
        _ykpiv_end_transaction(state);
        res
    }
}

static mut MGMT_AID : *const u8 = 0xa0i32 as (*const u8);

#[no_mangle]
pub unsafe extern fn ykpiv_auth_deauthenticate(
    mut state : *mut ykpiv_state
) -> Enum5 {
    let mut res : Enum5 = Enum5::YKPIV_OK;
    let mut apdu : u_APDU;
    let mut data : [u8; 255];
    let mut recv_len
        : u32
        = ::std::mem::size_of::<[u8; 255]>() as (u32);
    let mut sw : i32;
    if state.is_null() {
        Enum5::YKPIV_ARGUMENT_ERROR
    } else if {
                  res = _ykpiv_begin_transaction(state);
                  res
              } as (i32) < Enum5::YKPIV_OK as (i32) {
        res
    } else {
        if {
               res = _send_data(
                         state,
                         &mut apdu as (*mut u_APDU),
                         data.as_mut_ptr(),
                         &mut recv_len as (*mut u32),
                         &mut sw as (*mut i32)
                     );
               res
           } as (i32) < Enum5::YKPIV_OK as (i32) {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"Failed communicating with card: \'%s\'\n\0").as_ptr(),
                    ykpiv_strerror(res)
                );
            }
        } else if sw != 0x9000i32 {
            if (*state).verbose != 0 {
                fprintf(
                    __stderrp,
                    (*b"Failed selecting mgmt application: %04x\n\0").as_ptr(),
                    sw
                );
            }
            res = Enum5::YKPIV_GENERIC_ERROR;
        }
        _ykpiv_end_transaction(state);
        res
    }
}
