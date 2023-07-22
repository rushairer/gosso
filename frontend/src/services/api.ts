import axios from 'axios'

export async function getViewer() {
    const response = await axios.get(`/authentication/viewer?r=${Date.now()}`)
    if (response.status !== 200) {
        throw Error('network error')
    }

    if (!response.data?.id) {
        throw Error('error')
    }

    return response.data
}

export async function getClient(id: string) {
    const response = await axios.get(`/oauth2/client?id=${id}`)

    if (response.status !== 200) {
        throw Error('network error')
    }

    if (!response.data?.name) {
        throw Error('error')
    }

    return response.data
}
