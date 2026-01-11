package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	// 使用 ETH client 连接测试网
	client, err := ethclient.Dial("https://goerli.infura.io/v3/YOUR-PROJECT-ID")
	if err != nil {
		log.Fatal(err)
		return
	}

	// 获取私钥
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	// 获取公钥
	publicKey := privateKey.Public()
	// 类型断言为 *ecdsa.PublicKey
	publickeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	// 从公钥生成地址
	fromAddress := crypto.PubkeyToAddress(*publickeyECDSA)
	// 获取 nonce 值
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}
	// 获取 gas 价格
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	// 设置 gas 限制
	gasLimit := uint64(21000)
	// 设置转账金额
	value := big.NewInt(10000000000000000) // 0.01 ETH
	// 设置接收地址
	toAddress := common.HexToAddress("0x98990677D0E66cD80B7bD5887618B91B190d6c1B")
	// 设置数据字段为空
	var data []byte
	// 创建交易
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddress,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	// 签名交易
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	signTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// 发送交易
	err = client.SendTransaction(context.Background(), signTx)
	if err != nil {
		log.Fatal(err)
	}
	// 输出交易哈希
	log.Printf("tx sent: %s", signTx.Hash().Hex())

}
