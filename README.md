# ZJURate 项目后端

## chaincode

目前使用的是fabric-samples的测试网络
为了简化创建测试网络，写了两个脚本
先source setup-env.sh 再运行setup-network.sh
最后再运行go run main.go
注意修改脚本的路径

### TODO

目前注册账户分配CA证书的逻辑还没有搞明白，统一使用的是test-network org1上的appUser账户
图片的哈希上链也还没做
