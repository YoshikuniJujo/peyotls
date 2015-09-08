コードレビュー: 用意
====================

オレオレ認証局の作成
--------------------

	% cd /home/tatsuya/phd03_white/
	% mkdir oreore2
	% cd oreore2/
	% cp /etc/ssl/misc/CA.sh ./
	% cp /etc/ssl/openssl.cnf ./
	% vim CA.sh
	(以下を追加)
	SSLEAY_CONFIG="-config /home/tatsuya/phd03_white/oreore2/openssl.cnf"
	CATOP="/home/tatsuya/phd03_white/oreore2/"
	% vim openssl.cnf
	dir = /home/tatsuya/phd03_white/oreore2/
	default_bits = 2048
	countryName_default = JP
	stateOrProvinceName_default = Gunma
	0.organizationName_default = Yoshikuni
	% ./CA.sh -newca
	% ./CA.sh -newreq
	% ./CA.sh -sign
	% mkdir reqs
	% mv newreq.pem reqs/first_csr.pem
	% mv newreq.pem private/first_key.pem
	% mv newcert.pem certs/first_cert.pem

テスト用サーバ
--------------

### サーバ証明書の設定

### nginxの起動

	% sudo emerge -av nginx
	% sudo /etc/init.d/nginx start

テスト用クライアント
--------------------

### 証明書確認用のプロファイルの作成

1. Firefoxの終了
2. % firefox -P
3. 「新しいプロファイルを作成」
4. 「次へ」
5. test_cert2を入力
6. 「完了」

### プロファイルを指定してFirefoxを起動

% firefox -P test_cert2

### オレオレ認証局の自己署名証明書をインポートする

1. 「編集」
2. 「設定」
3. 「証明書を表示」
4. 「インポート」
5. oreore2/cacert.pem
