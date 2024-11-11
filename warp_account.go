package main

import (
	"errors"
	"fmt"
	"os"

	wgcfCloudflare "github.com/ViRb3/wgcf/v2/cloudflare"
	wgcfCmdShared "github.com/ViRb3/wgcf/v2/cmd/shared"
	wgcfConfig "github.com/ViRb3/wgcf/v2/config"
	wgcfWireguard "github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/pelletier/go-toml/v2"
)

type Account struct {
	PrivateKey  string                 `toml:"private_key"`
	DeviceId    string                 `toml:"device_id"`
	AccessToken string                 `toml:"access_token"`
	LicenseKey  string                 `toml:"license_key"`
	ThisDevice  *wgcfCloudflare.Device `toml:"this_device"`
}

func (acc *Account) tryToLoadFromConfig(accountConfigPath string) (wasSuccessful bool) {
	wgcfAccountToml, err := os.ReadFile(accountConfigPath)
	if err != nil {
		return false
	}

	err = toml.Unmarshal(wgcfAccountToml, acc)
	if err != nil {
		return false
	}

	if acc.PrivateKey == "" || acc.DeviceId == "" || acc.AccessToken == "" || acc.LicenseKey == "" || acc.ThisDevice == nil {
		return false
	}

	return true
}

func (acc *Account) saveToConfig(accountConfigPath string) error {
	file, err := os.Create(accountConfigPath)
	if err != nil {
		return fmt.Errorf("could not create a config file at '%s': %v", accountConfigPath, err)
	}
	defer file.Close() // todo: handle .Close() errors?

	err = toml.NewEncoder(file).Encode(acc)
	if err != nil {
		return fmt.Errorf("could not marshall an Account into '%s': %v", accountConfigPath, err)
	}

	return nil
}

func (acc *Account) register() error {
	var err error

	privateKey, err := wgcfWireguard.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("could not generate a wireguard private key: %v", err)
	}
	acc.PrivateKey = privateKey.String()

	device, err := wgcfCloudflare.Register(privateKey.Public(), "PC")
	if err != nil {
		return err
	}

	acc.DeviceId = device.Id
	acc.AccessToken = device.Token
	acc.LicenseKey = device.Account.License

	wgcfAccountContext := &wgcfConfig.Context{
		DeviceId:    acc.DeviceId,
		AccessToken: acc.AccessToken,
		PrivateKey:  acc.PrivateKey,
		LicenseKey:  acc.LicenseKey,
	}
	_, err = wgcfCmdShared.SetDeviceName(wgcfAccountContext, "")
	if err != nil {
		return fmt.Errorf("could not set cloudflare warp device name: %v", err)
	}

	acc.ThisDevice, err = wgcfCloudflare.GetSourceDevice(wgcfAccountContext)
	if err != nil {
		return fmt.Errorf("could not get cloudflare warp source device: %v", err)
	}

	boundDevice, err := wgcfCloudflare.UpdateSourceBoundDeviceActive(wgcfAccountContext, true)
	if err != nil {
		return fmt.Errorf("could not set current device to active: %v", err)
	}

	if !boundDevice.Active {
		return errors.New("current cloudflare warp device did not become active after activating")
	}

	return nil
}
