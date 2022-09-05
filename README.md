# security-txt-parser

A simple library for parsing security.txt files

## Download

```sh
go get github.com/asankov/security-txt-parser
```

## Usage

```go
import (
    "file"

    "github.com/asankov/security-txt-parser/security"
)

func main() {
    file, err := os.Open("security.txt")
    if err != nil {
        // handle error
    }

    defer file.Close()

    txt, err = security.Parse(file)
    if err != nil {
        // handle error
    }

    // use txt
}
```
