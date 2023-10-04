const statusModel = require("../../models/mongoose/status")

let status;
const CART_STATUSES = async () => {
  status = status || (await getStatus({type:'CART'}));
  return status;
};

const ORDER_STATUSES = async () => {
  status = status || (await getStatus({type:'ORDER'}));
  return status;
};

const USER_STATUSES = async () => {
  status = status || (await getStatus({type:'USER'}));
  return status;
};

const getStatus = async (query = {}) => {
  const statuses = await statusModel.find(query);
  return buildConstantObject(statuses);
};

const buildConstantObject = records => {
  let result = {};
  records.forEach(record => {
    result[`${record.name}`] = record._id;
  });
  return result;
};

module.exports = {
  CART_STATUSES,
  ORDER_STATUSES,
  USER_STATUSES
}