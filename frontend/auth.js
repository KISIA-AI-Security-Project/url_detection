// OAuth code + PKCE. Access/refresh tokens stay in memory, never in the bundle or browser storage.
export class AuthenticationRequired extends Error {
  constructor(message='로그인이 만료됐습니다. 다시 로그인해 주세요.') {super(message);this.status=401;}
}
export class WebAuth {
  constructor(config) {
    this.config = config;
    this.tokens = null;
    this.pendingRefresh = null;
  }
  static random() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
  }
  async login() {
    const verifier = WebAuth.random(), state = WebAuth.random();
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
    sessionStorage.setItem('web.oauth', JSON.stringify({verifier,state,created:Date.now()}));
    const url = new URL('/oauth2/authorize', this.config.domain);
    url.search = new URLSearchParams({
      client_id:this.config.client_id,response_type:'code',scope:this.config.scope,
      redirect_uri:this.config.redirect_uri,state,code_challenge:challenge,code_challenge_method:'S256'
    });
    location.assign(url);
  }
  async initialize() {
    const params = new URLSearchParams(location.search);
    if (!params.has('code') && !params.has('error')) return false;
    const stored = sessionStorage.getItem('web.oauth');
    sessionStorage.removeItem('web.oauth');
    history.replaceState(null,'',location.pathname);
    if (params.has('error')) throw new Error('로그인을 완료하지 못했습니다.');
    let pending;
    try {pending = JSON.parse(stored);} catch {throw new Error('로그인을 다시 시작해 주세요.');}
    if (!pending || params.get('state') !== pending.state ||
        Date.now()-pending.created > 600000) throw new Error('로그인 요청이 만료됐습니다. 다시 로그인해 주세요.');
    await this.exchange({grant_type:'authorization_code',code:params.get('code'),
      redirect_uri:this.config.redirect_uri,code_verifier:pending.verifier});
    return true;
  }
  async exchange(values) {
    const response = await fetch(new URL('/oauth2/token',this.config.domain), {
      method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({client_id:this.config.client_id,...values}),cache:'no-store'
    });
    if (!response.ok) {this.tokens=null;throw new AuthenticationRequired();}
    const tokens = await response.json();
    if (!tokens.access_token || !Number.isFinite(tokens.expires_in)) throw new Error('로그인 응답을 확인하지 못했습니다.');
    this.tokens = {...tokens,refresh_token:tokens.refresh_token || this.tokens?.refresh_token,
      expires_at:Date.now()+tokens.expires_in*1000};
  }
  async accessToken() {
    if (!this.tokens) throw new AuthenticationRequired('로그인 후 이용해 주세요.');
    if (this.tokens.expires_at-Date.now() < 45000) {
      if (!this.tokens.refresh_token) {this.tokens=null;throw new AuthenticationRequired();}
      if (!this.pendingRefresh) this.pendingRefresh = this.exchange({
        grant_type:'refresh_token',refresh_token:this.tokens.refresh_token
      }).finally(()=>{this.pendingRefresh=null;});
      await this.pendingRefresh;
    }
    return this.tokens.access_token;
  }
  logout() {
    this.tokens=null; sessionStorage.removeItem('web.oauth');sessionStorage.removeItem('web.activeScan');
    const url = new URL('/logout',this.config.domain);
    url.search = new URLSearchParams({client_id:this.config.client_id,logout_uri:this.config.redirect_uri});
    location.assign(url);
  }
}
