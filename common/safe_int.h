// safe_int<T>(value)
//
// Like static_cast<T>(value) for integral types, but additionally throws an
// exception at runtime if value does not fit in type T.  Both static_cast and
// safe_int prevent compiler warnings about conversions that may change the
// value.  You can think of safe_int as a message to the compiler "It may look
// like this conversion could change the value, but I know what I'm doing, so
// don't warn me.  But if I was wrong, tell me at runtime instead of just
// using a corrupt value."
//
// You should try to use consistent integer types whenever possible, but when
// it's not possible, safe_int can be useful.  In particular, it is useful
// when converting
// * an integer whose value is known to always be within the required range,
//   even though its type can hold values outside that range
// * to or from abstracted types like size_t or ptrdiff_t whose underlying
//   type is hidden or varies across platforms
//
// If SAFE_INT_NONFATAL is defined before including this header, no exception
// is thrown, but a diagnostic is printed to stderr.
//
// If SAFE_INT_DISABLE is defined before including this header, no checking or
// diagnostics are performed at runtime, making safe_int equivalent to a
// static_cast.  (You might want to define SAFE_INT_DISABLE whenever you
// define NDEBUG.)
//
// If the <cxxabi.h> header is available, you can define HAVE_CXXABI_H before
// including this header to demangle type names in the diagnostic messages.
//
// This operator is optimized to do as much checking as possible at compile
// time instead of runtime.  E.g., converting a uint16_t to a int32_t can
// never overflow, so safe_int would produce no additional runtime code.
//
// Example:
//   ssize_t n = read(fd, buf, count);
//   if (n < 0) {
//       handle_error();
//   } else {
//       unsigned bytes = safe_int<unsigned>(n);
//       ...
//   }
// 

#include <limits>
#include <sstream>
#include <typeinfo>

#ifdef HAVE_CXXABI_H
#include <cxxabi.h>
#endif // HAVE_CXXABI_H

#ifndef SAFE_INT_H
#define SAFE_INT_H

#ifndef SAFE_INT_DISABLE
 #ifndef SAFE_INT_NONFATAL
  #include <stdexcept>
 #else
  #include <iostream>
 #endif
#endif


// sp_enable_if<expr, T>::type will be equivalent to T iff expr is true.
// This is useful to create a template specialization based on expr.
// (Equivalent to std::enable_if in C++11.)
template<bool B, class T = void>
struct sp_enable_if {};
template<class T>
struct sp_enable_if<true, T> { typedef T type; };


class safe_int_class {
    template <typename T> class NL : public std::numeric_limits<T> {}; // shorthand
    const char * const &file;
    const int &line;

    class DemangledName {
#ifdef HAVE_CXXABI_H
	char *dname;
    public:
	DemangledName(const DemangledName &) NO_METHOD;
	DemangledName operator=(const DemangledName &) NO_METHOD;
	DemangledName(const char *name) : dname() {
	    size_t len = 0;
	    int status;
	    dname = abi::__cxa_demangle(name, nullptr, &len, &status);
	}
	~DemangledName() { free(dname); }
	const char *str() { return dname; }
#else
    public:
	DemangledName(const char *name ATR_UNUSED) {}
	const char *str() { return "target type"; }
#endif
    };

    template<typename S>
#ifndef SAFE_INT_DISABLE
    void check(const S &val, const char * const &name, const bool &ok) {
	if (!ok) {
	    std::ostringstream os;
	    os << "integer value " << val << " out of range of " <<
		DemangledName(name).str() << " at " << file << ":" << line;
#ifdef SAFE_INT_NONFATAL
	    std::cerr << "error: " << os.str() << "\n";
#else
	    throw std::runtime_error(os.str());
#endif
	}
    }
#else // SAFE_INT_DISABLE
    void check(const S &val ATR_UNUSED, const char * const &name ATR_UNUSED, const bool &expr ATR_UNUSED) { }
#endif

public:
    // constructor
    safe_int_class(const char * const &_file, const int &_line) : file(_file), line(_line) {}

    // shorthand
    #define SICONV(expr) \
	template <typename D/*estination*/, typename S/*ource*/> \
	typename sp_enable_if<expr, D>::type convert(const S &i)

    // unsigned -> wide-enough OR signed -> wide-enough signed
    SICONV((!NL<S>::is_signed || NL<D>::is_signed) && NL<D>::digits >= NL<S>::digits) {
	// can't fail
	return static_cast<D>(i);
    }

    // unsigned -> narrower
    SICONV(!NL<S>::is_signed && NL<D>::digits < NL<S>::digits) {
	// all bits of i will fit in D?
	check(i, typeid(D).name(), !(i >> NL<D>::digits));
	return static_cast<D>(i);
    }

    // signed -> narrower signed
    SICONV(NL<S>::is_signed && NL<D>::is_signed && NL<D>::digits < NL<S>::digits) {
	// i is in range?
	check(i, typeid(D).name(), i >= NL<D>::min() && i <= NL<D>::max());
	return static_cast<D>(i);
    }

    // signed -> wide-enough unsigned
    SICONV(NL<S>::is_signed && !NL<D>::is_signed && NL<D>::digits >= NL<S>::digits) {
	// i is nonnegative?
	check(i, typeid(D).name(), i >= 0);
	return static_cast<D>(i);
    }

    // signed -> narrower unsigned
    SICONV(NL<S>::is_signed && !NL<D>::is_signed && NL<D>::digits < NL<S>::digits) {
	// i is nonnegative and all bits of i will fit in D?
	check(i, typeid(D).name(), i >= 0 && !(i >> NL<D>::digits));
	return static_cast<D>(i);
    }

    #undef SICONV
};

#define safe_int  safe_int_class(__FILE__, __LINE__).convert

#endif // SAFE_INT_H
