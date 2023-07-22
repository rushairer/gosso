import type { cssFunction } from '@ant-design/use-emotion-css'

export const SimpleContainerClassFunction: cssFunction = () => {
    return {
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'auto',
        justifyContent: 'center',
        justifyItems: 'center',
        textAlign: 'center',
        width: '300px',
        margin: '0 auto',
        '& > *': {
            marginBottom: '15px',
        },
        '& > button > svg': {
            marginRight: '15px',
            height: '14px',
        },
        '& :last-child': {
            marginBottom: '0px',
        },
    }
}

export const ProfileContainerClassFunction: cssFunction = () => {
    return {
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'auto',
        justifyContent: 'center',
        justifyItems: 'center',
        width: '300px',
        margin: '0 auto',
    }
}
