package main

import (
	"os"
	"log"
	"time"
	"github.com/jonluo94/fabric-goclient"
	"io/ioutil"
)

func main()  {

    ordererDomain  := "orderer.example.com"
	orgs :=[]string{"Org1","Org2"}
	channelId := "mychannel"
	connectConfig,_ := ioutil.ReadFile("./first-network.yaml")
	goPath := os.Getenv("GOPATH")
	channelTx := goPath +"/src/github.com/hyperledger/fabric-samples/first-network/channel-artifacts/channel.tx"
    chaincodeId := "mycc"
	chaincodePath := "github.com/hyperledger/fabric-samples/chaincode/chaincode_example02/go"
	/*操作fabric start*/
	fabric := client.NewFabricClient(connectConfig, channelId ,orgs, ordererDomain)
	defer fabric.Close()
	fabric.Setup()
	//创建channel
	fabric.CreateChannel(channelTx)
	//加入channel
	fabric.JoinChannel()

	//初始化
	ccVersion := "0"
	ccPolicy := "OR ('Org1MSP.member','Org2MSP.member')"
	initArgs := [][]byte{[]byte("init"),[]byte("a"), []byte("100"), []byte("b"), []byte("200")}
	//安装cc
	fabric.InstallChaincode(chaincodeId,chaincodePath,ccVersion)
	//实例化cc
	fabric.InstantiateChaincode(chaincodeId,chaincodePath,ccVersion,ccPolicy,initArgs)
	//查询状态
	ledger,_ := fabric.QueryLedger()
	log.Println(string(ledger))

	//查询账本
	queryFcn := "query"
	queryArgs := [][]byte{[]byte("a")}
	a ,_:= fabric.QueryChaincode(chaincodeId,queryFcn,queryArgs)
	log.Println("a的值: ",string(a))
	//invoke 账本
	invokeFcn := "invoke"
	invokeArgs := [][]byte{[]byte("a"), []byte("b"), []byte("10")}
	txid,_ := fabric.InvokeChaincode(chaincodeId,invokeFcn,invokeArgs)
	log.Println(string(txid))
	time.Sleep(10 * time.Second)
	//查询账本
	a ,_ = fabric.QueryChaincode(chaincodeId,queryFcn,queryArgs)
	log.Println("a的值: ",string(a))
	//升级cc
	ccVersion = "1"
	fabric.UpgradeChaincode(chaincodeId,chaincodePath,ccVersion,ccPolicy,initArgs)

	//invoke账本
	txid ,_= fabric.InvokeChaincode(chaincodeId,invokeFcn,invokeArgs)
	log.Println(string(txid))
	time.Sleep(10 * time.Second)
	//查询账本
	a,_ = fabric.QueryChaincode(chaincodeId,queryFcn,queryArgs)
	log.Println("a的值: ",string(a))

}