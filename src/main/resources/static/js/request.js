const axiosApiInstance = axios.create();

let tokenStore = {
  access_token: '',
  refresh_token: ''
}


// Request interceptor for API calls
axiosApiInstance.interceptors.request.use(
  async config => {
    console.log('request interceptior', config);
    config.headers = { 
      'Authorization': `Bearer ${tokenStore.access_token}`,
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    return config;
  },
  error => Promise.reject(error)
);

// Response interceptor for API calls
axiosApiInstance.interceptors.response.use(
  (response) => response, 
  async (error) => {
    console.log('response interceptior', error);
    const originalRequest = error.config;
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const tokenBody = await refreshAccessToken();
      tokenStore.access_token = tokenBody.accessToken;
      document.cookie = "R_TOKEN=" + tokenBody.refreshToken;
      return axiosApiInstance(originalRequest);
    }
    return Promise.reject(error);
  }
);


const get = (url) => {
  return new Promise((resolve, reject) => {
    axiosApiInstance({
      method: 'GET',
      url: url,
      baseURL: document.location.origin,
      responseType: 'json',
      responseEncoding: 'utf8',
    })
    .then(res => resolve(res.data))
    .catch(err => reject(err));
  });
}

const post = (url, data) => {
  return new Promise((resolve, reject) => {
    axiosApiInstance({
      method: 'POST',
      url: url,
      data: data,
      baseURL: document.location.origin,
      responseType: 'json',
      responseEncoding: 'utf8',
    })
    .then(res => resolve(res.data))
    .catch(err => reject(err));
  });
}

const refreshAccessToken = () => {
  return new Promise((resolve, reject) => {
    axiosApiInstance({
      method: 'GET',
      url: '/refresh/token',
      baseURL: document.location.origin,
      responseType: 'json',
      responseEncoding: 'utf8',
    })
    .then(res => resolve(res.data.data))
    .catch(err => reject(err));
  });
}