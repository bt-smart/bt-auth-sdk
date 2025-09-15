# bt-auth-sdk
佰特授权服务sdk

# 如何使用
1. 使用authclient.NewAuthClient注册全局客户端
2. 需要保护的路由组注册 使用authclient.Middleware


示例
根据主键获取用户信息
```go
    user, err := client.User.Info(1)
	if err != nil {
		println(err.Error())
	}
	fmt.Printf("%+v\n", user) // 展示结构体字段和值
```

获取上下文中的数据
```go


// GetUserId 获取上下文中的userId
func GetUserId(c *gin.Context) uint64 {
	return c.GetUint64(ContextUserIDKey)
}

// GetClientId 获取上下文中的clientId
func GetClientId(c *gin.Context) uint64 {
	return c.GetUint64(ContextClientIDKey)
}


```