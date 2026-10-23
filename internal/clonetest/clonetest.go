// Package clonetest checks that a Clone function is a deep copy: that the
// copy shares no pointer, slice element or map with the value it was made
// from. It is a test helper and depends on the standard library only.
package clonetest

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"
)

// maxDepth bounds the walk through recursive types.
const maxDepth = 12

// Check fills every field of a T — exported or not, through every pointer,
// slice, array and map — clones it, then rewrites the original in place
// through the same pointers, slice elements and map entries. It fails t if
// the clone is not equal to the original before the rewrite, or if the
// rewrite reached the clone. Function, channel and interface fields are left
// zero.
func Check[T any](t testing.TB, clone func(T) T) {
	t.Helper()
	var orig, want T
	fill(reflect.ValueOf(&orig).Elem(), 1, 0)
	fill(reflect.ValueOf(&want).Elem(), 1, 0)
	c := clone(orig)
	if p := diff(reflect.ValueOf(&c).Elem(), reflect.ValueOf(&want).Elem(), ""); p != "" {
		t.Fatalf("%T: the clone differs from the original at %s", orig, p)
	}
	fill(reflect.ValueOf(&orig).Elem(), 2, 0)
	if reflect.DeepEqual(orig, want) {
		t.Fatalf("%T: rewriting the original changed nothing", orig)
	}
	if p := diff(reflect.ValueOf(&c).Elem(), reflect.ValueOf(&want).Elem(), ""); p != "" {
		t.Errorf("%T: the clone shares memory with the original at %s", orig, p)
	}
}

var (
	addrType     = reflect.TypeFor[netip.Addr]()
	addrPortType = reflect.TypeFor[netip.AddrPort]()
	prefixType   = reflect.TypeFor[netip.Prefix]()
	timeType     = reflect.TypeFor[time.Time]()
)

// fill writes seed-derived values into v in place: a non-nil pointer, slice
// or map is written through, not replaced, so that a value sharing it sees
// the write.
func fill(v reflect.Value, seed int, depth int) {
	if depth > maxDepth {
		return
	}
	if !v.CanSet() {
		v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	}
	ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(seed)})
	switch v.Type() {
	case addrType:
		v.Set(reflect.ValueOf(ip))
		return
	case addrPortType:
		v.Set(reflect.ValueOf(netip.AddrPortFrom(ip, uint16(seed))))
		return
	case prefixType:
		v.Set(reflect.ValueOf(netip.PrefixFrom(ip, 24+seed)))
		return
	case timeType:
		v.Set(reflect.ValueOf(time.Unix(int64(seed), 0)))
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(seed%2 == 1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(seed))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(uint64(seed))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(seed))
	case reflect.Complex64, reflect.Complex128:
		v.SetComplex(complex(float64(seed), 0))
	case reflect.String:
		v.SetString(fmt.Sprint("s", seed))
	case reflect.Array:
		for i := range v.Len() {
			fill(v.Index(i), seed, depth+1)
		}
	case reflect.Slice:
		if v.IsNil() {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		for i := range v.Len() {
			fill(v.Index(i), seed, depth+1)
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		key := reflect.New(v.Type().Key()).Elem()
		fill(key, 1, depth+1)
		val := reflect.New(v.Type().Elem()).Elem()
		if old := v.MapIndex(key); old.IsValid() {
			val.Set(old)
		}
		fill(val, seed, depth+1)
		v.SetMapIndex(key, val)
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fill(v.Elem(), seed, depth+1)
	case reflect.Struct:
		for i := range v.NumField() {
			fill(v.Field(i), seed, depth+1)
		}
	case reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Invalid:
	}
}

// diff is the path of the first difference between a and b, or "". Both
// are addressable.
func diff(a, b reflect.Value, path string) string {
	if a.Type() != b.Type() {
		return path + " (type)"
	}
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			if a.IsNil() != b.IsNil() {
				return path + " (nil)"
			}
			return ""
		}
		return diff(a.Elem(), b.Elem(), path)
	case reflect.Struct:
		if a.Type() == addrType || a.Type() == addrPortType || a.Type() == prefixType || a.Type() == timeType {
			break
		}
		for i := range a.NumField() {
			if p := diff(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name); p != "" {
				return p
			}
		}
		return ""
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return path + " (len)"
		}
		for i := range a.Len() {
			if p := diff(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
		return ""
	default:
	}
	if !reflect.DeepEqual(valueOf(a), valueOf(b)) {
		return path
	}
	return ""
}

// valueOf is the addressable v as an interface, read through unexported
// fields too.
func valueOf(v reflect.Value) any {
	if v.CanInterface() {
		return v.Interface()
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface()
}
