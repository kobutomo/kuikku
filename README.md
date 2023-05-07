# kuikku

QUIC の initial packet を解析、復号化する処理を書いてみたやつ

## 使い方

```shell
go run .
```

`input.go` に wireshark などでキャッチした QUIC の initial packet がベタ書きされているので、それを解析してもらう。( input1 は [RFC9001](https://www.rfc-editor.org/rfc/rfc9001.html#name-sample-packet-protection) に記載のサンプル initial packet)  
input を変更する際は `func main()` 内のローカル変数 `sampleImput` の定義を変更する。
