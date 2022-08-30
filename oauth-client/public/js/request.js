const axiosApiInstance = axios.create();


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