package client

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"log"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/cauthdsl"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"encoding/json"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"time"
	"fmt"
	"os"
)

type FabricClient struct {
	ConnectionFile []byte
	ChannelTx      string
	OrdererDomain  string
	Orgs           []string
	AnchorsTx      []string
	OrgAdmin       string
	UserName       string
	ChannelId      string
	GoPath         string

	resmgmtClients []*resmgmt.Client
	sdk            *fabsdk.FabricSDK
	retry          resmgmt.RequestOption
	orderer        resmgmt.RequestOption
}

func (f *FabricClient) Setup() {
	sdk, err := fabsdk.New(config.FromRaw(f.ConnectionFile,"yaml"))
	if err != nil {
		log.Println("failed to create SDK")
	}
	f.sdk = sdk

	resmgmtClients := make([]*resmgmt.Client, 0)
	for _, v := range f.Orgs {
		resmgmtClient, err := resmgmt.New(sdk.Context(fabsdk.WithUser(f.OrgAdmin), fabsdk.WithOrg(v)))
		if err != nil {
			log.Printf("Failed to create channel management client: %s", err)
		}
		resmgmtClients = append(resmgmtClients, resmgmtClient)
	}
	f.resmgmtClients = resmgmtClients

	f.retry = resmgmt.WithRetry(retry.DefaultResMgmtOpts)
	f.orderer = resmgmt.WithOrdererEndpoint(f.OrdererDomain)
}

func (f *FabricClient) Close() {
	if f.sdk != nil {
		f.sdk.Close()
	}
}

func (f *FabricClient) CreateChannel() {
	mspClient, err := mspclient.New(f.sdk.Context(), mspclient.WithOrg(f.Orgs[0]))
	if err != nil {
		log.Println(err)
	}
	adminIdentity, err := mspClient.GetSigningIdentity(f.OrgAdmin)
	if err != nil {
		log.Println(err)
	}
	req := resmgmt.SaveChannelRequest{
		ChannelID:         f.ChannelId,
		ChannelConfigPath: f.ChannelTx,
		SigningIdentities: []msp.SigningIdentity{adminIdentity},
	}
	txId, err := f.resmgmtClients[0].SaveChannel(req, f.retry, f.orderer)
	if err != nil {
		log.Println(err)
	}
	log.Println(txId)
}

func (f *FabricClient) UpdateChannel() {


	for i, c := range f.resmgmtClients {

		mspClient, err := mspclient.New(f.sdk.Context(), mspclient.WithOrg(f.Orgs[i]))
		if err != nil {
			log.Println(err)
		}
		adminIdentity, err := mspClient.GetSigningIdentity(f.OrgAdmin)
		if err != nil {
			log.Println(err)
		}
		req := resmgmt.SaveChannelRequest{
			ChannelID:         f.ChannelId,
			ChannelConfigPath: f.AnchorsTx[i],
			SigningIdentities: []msp.SigningIdentity{adminIdentity},
		}
		txId, err := c.SaveChannel(req, f.retry, f.orderer)
		if err != nil {
			log.Println(err)
		}
		log.Println(txId)
	}
}

func (f *FabricClient) JoinChannel() {

	for i, c := range f.resmgmtClients {
		err := c.JoinChannel(f.ChannelId, f.retry, f.orderer)
		if err != nil {
			log.Printf("Org peers failed to JoinChannel: %s", err)
		}
		log.Println(f.Orgs[i], " join channel")
	}

}

func (f *FabricClient) InstallChaincode(chaincodeId,chaincodePath,version string) {
	ccPkg, err := gopackager.NewCCPackage(chaincodePath, f.GoPath)
	if err != nil {
		log.Println(err)
	}

	req := resmgmt.InstallCCRequest{
		Name:    chaincodeId,
		Path:    chaincodePath,
		Version: version,
		Package: ccPkg,
	}

	for _, c := range f.resmgmtClients {
		res, err := c.InstallCC(req, f.retry)
		if err != nil {
			log.Println(err)
		}
		log.Println(res)
	}

}

func (f *FabricClient) InstantiateChaincode(chaincodeId,chaincodePath,version string, policy string, args [][]byte) {

	//"OR ('Org1MSP.member','Org2MSP.member')"
	ccPolicy, err := cauthdsl.FromString(policy)
	if err != nil {
		log.Println(err)
	}
	resp, err := f.resmgmtClients[0].InstantiateCC(
		f.ChannelId,
		resmgmt.InstantiateCCRequest{
			Name:    chaincodeId,
			Path:    chaincodePath,
			Version: version,
			Args:    args,
			Policy:  ccPolicy,
		},
		f.retry,
	)

	log.Println(resp)
}

func (f *FabricClient) UpgradeChaincode(chaincodeId,chaincodePath,version string, policy string, args [][]byte) {

	f.InstallChaincode(chaincodeId,chaincodePath,version)

	ccPolicy, err := cauthdsl.FromString(policy)
	if err != nil {
		log.Println(err)
	}
	resp, err := f.resmgmtClients[0].UpgradeCC(
		f.ChannelId,
		resmgmt.UpgradeCCRequest{
			Name:    chaincodeId,
			Path:    chaincodePath,
			Version: version,
			Args:    args,
			Policy:  ccPolicy,
		},
		f.retry,
	)
	log.Println(resp)
}

func (f *FabricClient) QueryLedger() []byte{

	ledger, err := ledger.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
	}

	bci, err := ledger.QueryInfo()
	if err != nil {
		log.Println(err)
	}
	bcis,err := json.Marshal(bci.BCI)
	if err != nil {
		log.Println(err)
	}
	log.Println(string(bcis))
	return bcis
}


func (f *FabricClient) QueryChaincode(chaincodeId,fcn string,args [][]byte) []byte{

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
	}

	resp, err := client.Query(channel.Request{
		ChaincodeID: chaincodeId,
		Fcn:       fcn  ,
		Args:  args,
	})
	if err != nil {
		log.Println(err)
	}
	log.Println(string(resp.Payload))
	return resp.Payload
}


func (f *FabricClient) InvokeChaincodeWithEvent(chaincodeId,fcn string,args [][]byte) []byte{
	eventId := fmt.Sprintf("event%d",time.Now().UnixNano())

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
	}
	// 注册事件
	reg, notifier, err := client.RegisterChaincodeEvent(chaincodeId, eventId)
	if err != nil {
		log.Printf("注册链码事件失败: %s", err)
	}
	defer client.UnregisterChaincodeEvent(reg)

	req := channel.Request{
		ChaincodeID: chaincodeId,
		Fcn:         fcn,
		Args:        append(args,[]byte(eventId)),
	}
	resp, err := client.Execute(req)
	if err != nil {
		log.Println(err)
	}

	select {
	case ccEvent := <-notifier:
		log.Printf("接收到链码事件: %v\n", ccEvent)
	     return []byte(ccEvent.TxID)
	case <-time.After(time.Second * 30):
		log.Println("不能根据指定的事件ID接收到相应的链码事件")
	}
	return []byte(resp.TransactionID)
}

func (f *FabricClient) InvokeChaincode(chaincodeId,fcn string,args [][]byte) []byte{

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
	}
	req := channel.Request{
		ChaincodeID: chaincodeId,
		Fcn:         fcn,
		Args:        args,
	}
	resp, err := client.Execute(req)
	if err != nil {
		log.Println(err)
	}
	return []byte(resp.TransactionID)
}


func NewFabricClient(connectionFile []byte,channelTx string,channelId string,orgs []string,anchorsTx []string,orderer string) *FabricClient {
	fabric := &FabricClient{
		ConnectionFile:connectionFile,
		AnchorsTx      :anchorsTx,
		ChannelTx      :channelTx,
		ChannelId      :channelId,
		OrdererDomain  :orderer,
		Orgs           :orgs,
		OrgAdmin       :"Admin",
		UserName       :"User1",
		GoPath         :os.Getenv("GOPATH"),
	}

	return fabric

}