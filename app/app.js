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

document.querySelectorAll('[data-pk-verify]').forEach(el => {
  el.addEventListener('click', async ev => {
    ev.preventDefault()
    const url = el.dataset.pkVerify
    const { publicKey } = await (await fetch(url)).json()
    publicKey.challenge = Uint8Array.fromBase64(publicKey.challenge, b64url)
    const getResponse = await navigator.credentials.get({ publicKey })
    const form = el.closest('form')
    form.json.value = JSON.stringify(getResponse)
    form.submit()
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

/** @type {Intl.RelativeTimeFormat | null} */
let rtf
function toRelativeTime(futureInstant) {
  if (!rtf) rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const diffSecs = Temporal.Now.instant().until(futureInstant).total('seconds')
  const absSecs = Math.abs(diffSecs)

  if (absSecs < 60) return rtf.format(Math.round(diffSecs), 'seconds')
  if (absSecs < 3600) return rtf.format(Math.round(diffSecs / 60), 'minutes')
  if (absSecs < 86400) return rtf.format(Math.round(diffSecs / 3600), 'hours')
  return rtf.format(Math.round(diffSecs / 86400), 'days')
}

document.querySelectorAll('[data-rel-time]').forEach(el => {
  const input = el.dataset.relTime ? el.dataset.relTime : el.innerText
  const instant = Temporal.Instant.from(input)
  el.title = input
  el.textContent = toRelativeTime(instant)
})
