function jsonForm(url, v) {
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = url
  form.style.display = 'none'
  const input = document.createElement('input')
  input.name = 'json'
  input.value = JSON.stringify(v)
  form.appendChild(input)
  document.body.appendChild(form)
  form.submit()
}

const b64url = { alphabet: 'base64url' }

document.querySelectorAll('[data-pk-create]').forEach(el => {
  el.addEventListener('click', async () => {
    const url = el.dataset.pkCreate
    const { publicKey } = await (await fetch(url)).json()
    publicKey.challenge = Uint8Array.fromBase64(publicKey.challenge, b64url)
    publicKey.user.id = Uint8Array.fromBase64(publicKey.user.id, b64url)
    const createResponse = await navigator.credentials.create({ publicKey })
    jsonForm(url, createResponse)
  })
})

document.querySelectorAll('[data-pk-get]').forEach(el => {
  el.addEventListener('click', async () => {
    const url = el.dataset.pkGet
    const { publicKey } = await (await fetch(url)).json()
    publicKey.challenge = Uint8Array.fromBase64(publicKey.challenge, b64url)
    const getResponse = await navigator.credentials.get({ publicKey })
    jsonForm(url, getResponse)
  })
})

document.querySelectorAll('[data-share]').forEach(el => {
  el.addEventListener('click', async () => {
    await navigator.share(JSON.parse(el.dataset.share))
  })
})

document.querySelectorAll('[data-clip]').forEach(el => {
  el.addEventListener('click', async () => {
    await navigator.clipboard.writeText(el.dataset.clip)
  })
})
