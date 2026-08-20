let body = $response.body;

if (body) {
  try {
    let obj = JSON.parse(body);

    if (obj?.data?.vip && !obj.data.vip.status) {
      obj.data.vip.type = 2;
      obj.data.vip.status = 1;
      obj.data.vip.vip_pay_type = 1;
      obj.data.vip.due_date = 466982416e4;
    }

    body = JSON.stringify(obj);
  } catch (e) {
    console.log("bilibili myinfo error: " + e);
  }
}

$done({ body });
