# bt-auth-sdk
佰特授权服务sdk

# 如何使用
1. 使用authclient.NewAuthClient注册全局客户端
2. 需要保护的路由组注册 使用authclient.Middleware


示例
获取用户相亲
```go
    user, err := client.User.Info(1)
	if err != nil {
		println(err.Error())
	}
	fmt.Printf("%+v\n", user) // 展示结构体字段和值
```