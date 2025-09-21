;; Minimal WASM plugin (text format). Returns a fixed JSON with set_headers
;; Host expects exports: memory, alloc, dealloc, dispa_on_request, dispa_on_response, dispa_get_result_len

(module
  (memory (export "memory") 1)
  (global $result_len (mut i32) (i32.const 0))
  (global $result_ptr (mut i32) (i32.const 2048))

  ;; Preload a JSON string at offset 2048
  (data (i32.const 2048) "{\"set_headers\":{\"x-wasm\":\"1\"}}")

  ;; alloc returns a dummy pointer for host to write input; we ignore it
  (func (export "alloc") (param $n i32) (result i32)
    (i32.const 1024)
  )

  ;; dealloc is a no-op in this simple example
  (func (export "dealloc") (param $ptr i32) (param $len i32)
    (nop)
  )

  (func $set_result (result i32)
    ;; set result_len and return pointer to JSON
    (global.set $result_len (i32.const 27)) ;; length of the JSON below
    (global.get $result_ptr)
  )

  ;; request handler: ignore input and return fixed JSON
  (func (export "dispa_on_request") (param $ptr i32) (param $len i32) (result i32)
    (call $set_result)
  )

  ;; response handler: ignore input and return fixed JSON
  (func (export "dispa_on_response") (param $ptr i32) (param $len i32) (result i32)
    (call $set_result)
  )

  (func (export "dispa_get_result_len") (result i32)
    (global.get $result_len)
  )
)

