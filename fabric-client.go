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

const (
	Admin = "Admin"
	User  = "User1"
)
type FabricClient struct {
	ConnectionFile []byte
	OrdererDomain  string
	Orgs           []string
	OrgAdmin       string
	UserName       string
	ChannelId      string
	GoPath         string

	resmgmtClients []*resmgmt.Client
	sdk            *fabsdk.FabricSDK
	retry          resmgmt.RequestOption
	orderer        resmgmt.RequestOption
}

func (f *FabricClient) Setup() error {
	sdk, err := fabsdk.New(config.FromRaw(f.ConnectionFile,"yaml"))
	if err != nil {
		log.Println("failed to create SDK")
		return err
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

	return nil
}

func (f *FabricClient) Close() {
	if f.sdk != nil {
		f.sdk.Close()
	}
}

func (f *FabricClient) CreateChannel(channelTx string) error{
	mspClient, err := mspclient.New(f.sdk.Context(), mspclient.WithOrg(f.Orgs[0]))
	if err != nil {
		log.Println(err)
		return err
	}
	adminIdentity, err := mspClient.GetSigningIdentity(f.OrgAdmin)
	if err != nil {
		log.Println(err)
		return err
	}
	req := resmgmt.SaveChannelRequest{
		ChannelID:         f.ChannelId,
		ChannelConfigPath: channelTx,
		SigningIdentities: []msp.SigningIdentity{adminIdentity},
	}
	txId, err := f.resmgmtClients[0].SaveChannel(req, f.retry, f.orderer)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println(txId)
	return nil
}

func (f *FabricClient) UpdateChannel(anchorsTx []string) error{


	for i, c := range f.resmgmtClients {

		mspClient, err := mspclient.New(f.sdk.Context(), mspclient.WithOrg(f.Orgs[i]))
		if err != nil {
			log.Println(err)
			return err
		}
		adminIdentity, err := mspClient.GetSigningIdentity(f.OrgAdmin)
		if err != nil {
			log.Println(err)
			return err
		}
		req := resmgmt.SaveChannelRequest{
			ChannelID:         f.ChannelId,
			ChannelConfigPath: anchorsTx[i],
			SigningIdentities: []msp.SigningIdentity{adminIdentity},
		}
		txId, err := c.SaveChannel(req, f.retry, f.orderer)
		if err != nil {
			log.Println(err)
			return err
		}
		log.Println(txId)
	}

	return nil
}

func (f *FabricClient) JoinChannel() error{

	for i, c := range f.resmgmtClients {
		err := c.JoinChannel(f.ChannelId, f.retry, f.orderer)
		if err != nil {
			log.Printf("Org peers failed to JoinChannel: %s", err)
			return err
		}
		log.Println(f.Orgs[i], " join channel")
	}
	return nil

}

func (f *FabricClient) InstallChaincode(chaincodeId,chaincodePath,version string) error{
	ccPkg, err := gopackager.NewCCPackage(chaincodePath, f.GoPath)
	if err != nil {
		log.Println(err)
		return err
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
			return err
		}
		log.Println(res)
	}

	return nil
}

func (f *FabricClient) InstantiateChaincode(chaincodeId,chaincodePath,version string, policy string, args [][]byte) ([]byte,error){

	//"OR ('Org1MSP.member','Org2MSP.member')"
	ccPolicy, err := cauthdsl.FromString(policy)
	if err != nil {
		log.Println(err)
		return nil,err
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
	log.Println(resp.TransactionID)
	return []byte(resp.TransactionID),nil
}

func (f *FabricClient) UpgradeChaincode(chaincodeId,chaincodePath,version string, policy string, args [][]byte) ([]byte,error){

	f.InstallChaincode(chaincodeId,chaincodePath,version)

	ccPolicy, err := cauthdsl.FromString(policy)
	if err != nil {
		log.Println(err)
		return nil,err
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
	log.Println(resp.TransactionID)
	return []byte(resp.TransactionID),nil
}

func (f *FabricClient) QueryLedger() ([]byte,error){

	ledger, err := ledger.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
		return nil,err
	}

	bci, err := ledger.QueryInfo()
	if err != nil {
		log.Println(err)
		return nil,err
	}
	bcis,err := json.Marshal(bci.BCI)
	if err != nil {
		log.Println(err)
		return nil,err
	}
	log.Println(string(bcis))
	return bcis,nil
}


func (f *FabricClient) QueryChaincode(chaincodeId,fcn string,args [][]byte) ([]byte,error){

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
		return nil,err
	}

	resp, err := client.Query(channel.Request{
		ChaincodeID: chaincodeId,
		Fcn:       fcn  ,
		Args:  args,
	})
	if err != nil {
		log.Println(err)
		return nil,err
	}
	log.Println(string(resp.Payload))
	return resp.Payload,nil
}


func (f *FabricClient) InvokeChaincodeWithEvent(chaincodeId,fcn string,args [][]byte) ([]byte,error){
	eventId := fmt.Sprintf("event%d",time.Now().UnixNano())

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
		return nil,err
	}
	// 注册事件
	reg, notifier, err := client.RegisterChaincodeEvent(chaincodeId, eventId)
	if err != nil {
		log.Printf("注册链码事件失败: %s", err)
		return nil,err
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
		return nil,err
	}

	select {
	case ccEvent := <-notifier:
		log.Printf("接收到链码事件: %v\n", ccEvent)
	     return []byte(ccEvent.TxID),nil
	case <-time.After(time.Second * 30):
		log.Println("不能根据指定的事件ID接收到相应的链码事件")
		return nil,fmt.Errorf("%s","等到事件超时")
	}
	return []byte(resp.TransactionID),nil
}

func (f *FabricClient) InvokeChaincode(chaincodeId,fcn string,args [][]byte) ([]byte,error){

	client, err := channel.New(f.sdk.ChannelContext(f.ChannelId, fabsdk.WithUser(f.UserName), fabsdk.WithOrg(f.Orgs[0])))
	if err != nil {
		log.Println(err)
		return nil,err
	}
	req := channel.Request{
		ChaincodeID: chaincodeId,
		Fcn:         fcn,
		Args:        args,
	}
	resp, err := client.Execute(req)
	if err != nil {
		log.Println(err)
		return nil,err
	}
	return []byte(resp.TransactionID),nil
}


func NewFabricClient(connectionFile []byte,channelId string,orgs []string,orderer string) *FabricClient {
	fabric := &FabricClient{
		ConnectionFile:connectionFile,
		ChannelId      :channelId,
		OrdererDomain  :orderer,
		Orgs           :orgs,
		OrgAdmin       :Admin,
		UserName       :User,
		GoPath         :os.Getenv("GOPATH"),
	}

	return fabric

}