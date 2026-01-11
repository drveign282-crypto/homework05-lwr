package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
)

func main() {
	client, err := ethclient.Dial("https://sepolia.infura.io/v3/ade7fa2b871544f9bd1f614ca50520ff")
	if err != nil {
		log.Fatal(err)
	}
	// 查询区块
	//selectBlock(client)
	// 查询交易
	//selectTransaction(client)
	// 查询完整区块的交易依据
	//selectTransactionReceipt(client)
	// 创建新钱包
	//createdWallet()
	// ETH转账
	sendTransaction(client)
	// 代币转账
	//sendErc20Transaction(client)
	// 查询账户余额
	//selectBalance(client)
	// 订阅最新区块
	subscribeNewHead(client)
}

func subscribeNewHead(client2 *ethclient.Client) {
	client, err := ethclient.Dial("wss://sepolia.infura.io/ws/v3/ade7fa2b871544f9bd1f614ca50520ff")
	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			fmt.Println(header.Hash().Hex()) // 0xbc10defa8dda384c96a17640d84de5578804945d347072e091b4e5f390ddea7f
			block, err := client.BlockByHash(context.Background(), header.Hash())
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(block.Hash().Hex())        // 0xbc10defa8dda384c96a17640d84de5578804945d347072e091b4e5f390ddea7f
			fmt.Println(block.Number().Uint64())   // 3477413
			fmt.Println(block.Time())              // 1529525947
			fmt.Println(block.Nonce())             // 130524141876765836
			fmt.Println(len(block.Transactions())) // 7
		}
	}
}

func selectBalance(client *ethclient.Client) {
	account := common.HexToAddress("0x25836239F7b632635F815689389C537133248edb")
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balance)
	blockNumber := big.NewInt(5532993)
	balanceAt, err := client.BalanceAt(context.Background(), account, blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balanceAt) // 25729324269165216042
	fbalance := new(big.Float)
	fbalance.SetString(balanceAt.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	fmt.Println(ethValue) // 25.729324269165216041
	pendingBalance, err := client.PendingBalanceAt(context.Background(), account)
	fmt.Println(pendingBalance) // 25729324269165216042
}

func sendErc20Transaction(client *ethclient.Client) {
	// 获取账户私钥
	privateKey, err := crypto.HexToECDSA("账户私钥")
	if err != nil {
		log.Fatal(err)
	}
	// 获取公钥地址
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	// 获取 data 参数
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress) // 获取账户 nonce 值
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(0)                                        // 代币转账，转账金额为 0
	gasPrice, err := client.SuggestGasPrice(context.Background()) // 获取当前 gas 价格
	if err != nil {
		log.Fatal(err)
	}

	toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")    // 接收代币地址
	tokenAddress := common.HexToAddress("0x28b149020d2152179873ec60bed6bf7cd705775d") // 代币合约地址
	transferFnSignature := []byte("transfer(address,uint256)")                        // 代币转账函数签名
	hash := sha3.NewLegacyKeccak256()                                                 // 创建 Keccak256 哈希对象
	hash.Write(transferFnSignature)                                                   // 对函数签名做哈希
	methodID := hash.Sum(nil)[:4]                                                     // 取前4字节作为方法ID
	fmt.Println(hexutil.Encode(methodID))                                             // 0xa9059cbb

	// 拼接参数
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32) // 地址参数左填充到32字节
	amount := new(big.Int)                                      // 转账金额
	amount.SetString("1000000000000000000000", 10)              // 转成大整数类型，不能直接赋值 1000，1000 只是整数，单位不是 wei，精度不够。因为以太坊的代币数量通常需要用 *big.Int 类型表示，且单位是最小单位（如 1 token = 10^18 wei）
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)     // 金额参数左填充到32字节
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	// 估算 gasLimit 值
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		log.Fatal(err)
	}
	// 创建交易
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &tokenAddress,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})

	// 获取链ID
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 签名交易
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// 发送交易
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	// 打印交易哈希值，然后去测试网查询这笔交易
	fmt.Printf("tx sent: %s", signedTx.Hash().Hex()) // tx sent: 0xa56316b637a94c4cc0331c73ef26389d6c097506d581073f927275e7a6ece0bc
}

func sendTransaction(client *ethclient.Client) {
	// 替换成自己钱包的 sepolia 账户私钥 1 【已测试成功，删掉自己的私钥】
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	// 获取公钥地址
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	// 获取账户 nonce 值
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}
	// 设置转账金额 0.01 ETH
	value := big.NewInt(10000000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)              // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 替换成自己钱包的 sepolia 账户地址
	toAddress := common.HexToAddress("0x98990677D0E66cD80B7bD5887618B91B190d6c1B") //
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
	// 获取链ID
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	// 签名交易
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// 发送交易
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}
	// 打印交易哈希值，然后去测试网查询这笔交易: 0x4cb54feacfdddf766bc060a2526b88b9fcde2b4729f5d5c8eec326827b2cafea
	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())
}

func createdWallet() {
	// 生成随机私钥【生成钱包的核心代码，后面的所有计算推到都是基于这个随机生成的私钥进行的】
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	// 加密私钥并打印
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println(hexutil.Encode(privateKeyBytes)[2:]) // 打印私钥，去掉0x前缀：7ebeb613eb0b8d1e913a5fd0fe66060d65d2f49e719c0d34906ddd35c7de0af5
	// 由私钥获取公钥并打印
	publicKey := privateKey.Public()                   // 获取公钥接口
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey) // 类型断言为椭圆曲线公钥
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	// 直接生成地址并打印
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex() // 通过公钥生成以太坊地址（Keccak256哈希后取后 20 字节）
	fmt.Println(address)
	// 手动计算地址并打印【crypto.PubkeyToAddress 方法的实现原理】
	hash := sha3.NewLegacyKeccak256() // 创建 Keccak256 哈希对象
	hash.Write(publicKeyBytes[1:])    // 对公钥去掉首字节（0x04）后剩余 64 字节做哈希
	fmt.Println("full:", hexutil.Encode(hash.Sum(nil)[:]))
	fmt.Println(hexutil.Encode(hash.Sum(nil)[12:])) // 原长32位，截去12位，保留后20位
}

func selectTransactionReceipt(client *ethclient.Client) {
	blockNumber := big.NewInt(5671744)
	blockHash := common.HexToHash("0xae713dea1419ac72b928ebe6ba9915cd4fc1ef125a606f90f5e783c47cb1a4b5")
	// 方法 1：调用BlockReceipts方法获取指定区块中所有的收据列表。【参数可以是区块的 哈希值 也可以是区块的 高度 】
	receiptByHash, err := client.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(blockHash, false)) //使用区块哈希值
	if err != nil {
		log.Fatal(err)
	}
	// 睡眠几秒钟，避免出现请求过多的错误
	time.Sleep(6 * time.Second)
	receiptsByNum, err := client.BlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(blockNumber.Int64()))) // 使用区块高度
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(receiptByHash[0] == receiptsByNum[0]) // true

	for _, receipt := range receiptByHash {
		fmt.Println(receipt.Status)                // 1
		fmt.Println(receipt.Logs)                  // []
		fmt.Println(receipt.TxHash.Hex())          // 0x20294a03e8766e9aeab58327fc4112756017c6c28f6f99c7722f4a29075601c5
		fmt.Println(receipt.TransactionIndex)      // 0
		fmt.Println(receipt.ContractAddress.Hex()) // 0x0000000000000000000000000000000000000000
		break
	}

	// 方法 2：根据指定的交易哈希值获取指定交易的单个交易收据，调用 TransactionReceipt 方法
	txHash := common.HexToHash("0x20294a03e8766e9aeab58327fc4112756017c6c28f6f99c7722f4a29075601c5")
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(receipt.Status)                // 1
	fmt.Println(receipt.Logs)                  // []
	fmt.Println(receipt.TxHash.Hex())          // 0x20294a03e8766e9aeab58327fc4112756017c6c28f6f99c7722f4a29075601c5
	fmt.Println(receipt.TransactionIndex)      // 0
	fmt.Println(receipt.ContractAddress.Hex()) // 0x0000000000000000000000000000000000000000
}

func selectTransaction(client *ethclient.Client) {
	// 获取链ID
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 获取交易信息方法 1：获取完整 block 信息，然后从中获取交易信息
	blockNumber := big.NewInt(5671744)
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	// 遍历block里的交易信息
	for _, tx := range block.Transactions() {
		fmt.Println(tx.Hash().Hex())
		fmt.Println(tx.Value().String())
		fmt.Println(tx.Gas())
		fmt.Println(tx.GasPrice().Uint64())
		fmt.Println(tx.Nonce())
		fmt.Println(tx.Data())
		if tx.To() != nil {
			fmt.Println(tx.To().Hex())
		} else {
			fmt.Println("Contract Creation")
		}

		// 获取交易发起人，即 from
		var sender common.Address
		var err error
		switch tx.Type() {
		case types.LegacyTxType:
			sender, err = types.Sender(types.NewEIP155Signer(chainID), tx)
		case types.AccessListTxType, types.DynamicFeeTxType:
			sender, err = types.Sender(types.LatestSignerForChainID(chainID), tx)
		default:
			// 只有测试网才会有，正式网暂时未支持类型 3 的交易类型
			err = fmt.Errorf("未知交易类型: %d", tx.Type())
		}
		if err == nil {
			fmt.Println("Sender: ", sender.Hex())
		} else {
			log.Println(err) // 用log.Println避免直接退出，继续遍历
			continue
		}

		// 获取交易收据信息
		receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(receipt.Status)
		fmt.Println(receipt.Logs)
	}

	// 获取交易信息方法 2：调用客户端的 TransactionInBlock 方法【前提是要知道对应 block 的哈希值】
	hash := common.HexToHash("0xae713dea1419ac72b928ebe6ba9915cd4fc1ef125a606f90f5e783c47cb1a4b5")
	count, err := client.TransactionCount(context.Background(), hash)
	if err != nil {
		log.Fatal(err)
	}
	for idx := uint(0); idx < count; idx++ {
		tx, err := client.TransactionInBlock(context.Background(), hash, idx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tx.Hash().Hex())
	}

	// 获取交易信息方法 3：根据指定的交易哈希值直接查询，相当于 GetById
	txHash := common.HexToHash("0xa7ce4609db434f2d4c1bd357c04dfb850456fd38804cf326ed674b01dbd29fc9")
	tx, pending, err := client.TransactionByHash(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tx.Hash().Hex())
	fmt.Println(pending)
}

func selectBlock(client *ethclient.Client) {
	blockNumber := big.NewInt(5671744)

	header, err := client.HeaderByNumber(context.Background(), blockNumber)
	fmt.Println(header.Number.Uint64())     // 5671744
	fmt.Println(header.Time)                // 1712798400
	fmt.Println(header.Difficulty.Uint64()) // 0
	fmt.Println(header.Hash().Hex())        // 0xae713dea1419ac72b928ebe6ba9915cd4fc1ef125a606f90f5e783c47cb1a4b5

	if err != nil {
		log.Fatal(err)
	}
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(block.Number().Uint64())     // 5671744
	fmt.Println(block.Time())                // 1712798400
	fmt.Println(block.Difficulty().Uint64()) // 0
	fmt.Println(block.Hash().Hex())          // 0xae713dea1419ac72b928ebe6ba9915cd4fc1ef125a606f90f5e783c47cb1a4b5
	fmt.Println(len(block.Transactions()))   // 70
	count, err := client.TransactionCount(context.Background(), block.Hash())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(count) // 70
}
