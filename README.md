# sha1ct

Compile-Time sha1

```d
import sha1ct;

enum hash = sha1Of(cast(ubyte[]) [0, 1, 2, 3]); // Binary Data
enum hash2 = sha1Of("Hello World"); // String
enum namespace = sha1UUID("my.app"); // generates a std.uuid.UUID from string or binary
enum uuid = sha1UUID("interface1", namespace); // also with namespaces
```