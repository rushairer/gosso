import MetaMaskOnboarding from '@metamask/onboarding'
import React from 'react'
import { ReactComponent as IconMetamask } from '../assets/images/icon_metamask.svg'
import { Button, Typography } from 'antd'
import { useBoolean } from 'ahooks'
import { useEffect, useRef, useState } from 'react'
import moment from 'moment'

const ONBOARD_TEXT = '点击安装MetaMask'
const CONNECT_TEXT = '链接 MetaMask'
const CONNECTED_TEXT = '通过 MetaMask 登录'
const { Text } = Typography
type EthereumWindow = Window & typeof globalThis & { ethereum: any }
const ethereumWindow = window as EthereumWindow
const MetamaskButton: React.FC = () => {
    const [isConnected, toggleIsConnected] = useBoolean(false)
    const onboarding = useRef<MetaMaskOnboarding>()
    const [buttonText, setButtonText] = useState(ONBOARD_TEXT)
    const [accounts, setAccounts] = useState<string[]>([])

    useEffect(
        () => {
            if (!onboarding.current) {
                onboarding.current = new MetaMaskOnboarding()
            }

            if (MetaMaskOnboarding.isMetaMaskInstalled()) {
                ethereumWindow.ethereum.on('accountsChanged', setAccounts)
                return () => {
                    ethereumWindow.ethereum.removeListener(
                        'accountsChanged',
                        setAccounts
                    )
                }
            }
        },
        // eslint-disable-next-line react-hooks/exhaustive-deps
        []
    )

    useEffect(
        () => {
            if (MetaMaskOnboarding.isMetaMaskInstalled()) {
                if (accounts.length > 0) {
                    setButtonText(CONNECTED_TEXT)
                    toggleIsConnected.set(true)
                    onboarding.current?.stopOnboarding()
                } else {
                    setButtonText(CONNECT_TEXT)
                    toggleIsConnected.set(false)
                }
            }
        },
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [accounts]
    )

    const onClick = () => {
        if (MetaMaskOnboarding.isMetaMaskInstalled()) {
            if (isConnected) {
                const selectedAddress = ethereumWindow.ethereum.selectedAddress
                const expiresAt = moment().add(3, 'minutes').format().toString()

                ethereumWindow.ethereum
                    .request({
                        method: 'personal_sign',
                        params: [
                            `Apigg Account Center 希望使用您的地址(${selectedAddress})作为登录用户名，有效期至(${expiresAt})请签名授权。`,
                            selectedAddress,
                        ],
                    })
                    .then((signature: string) => {
                        window.location.href = `/socials/auth/ethereum?address=${selectedAddress}&signature=${signature}&expires_at=${encodeURIComponent(
                            expiresAt
                        )}`
                    })
                    .catch((error: Error) => console.debug(error))
            } else {
                ethereumWindow.ethereum
                    .request({ method: 'eth_requestAccounts' })
                    .then((newAccounts: any) => setAccounts(newAccounts))
            }
        } else {
            onboarding.current?.startOnboarding()
        }
    }

    return (
        <Button type="primary" size="large" block onClick={onClick}>
            <IconMetamask />
            <Text>{buttonText}</Text>
        </Button>
    )
}

export default MetamaskButton
