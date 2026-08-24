package internal

// ConcatBytes concatenates multiple byte slices into a single contiguous slice.
// It pre-allocates the full size to avoid reallocation.
func ConcatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// SwapEndianBytes ...
func SwapEndianBytes(data []byte) []byte {
	swapSlice := make([]byte, len(data))
	for i := range data {
		swapSlice[len(data)-1-i] = data[i]
	}

	return swapSlice
}
