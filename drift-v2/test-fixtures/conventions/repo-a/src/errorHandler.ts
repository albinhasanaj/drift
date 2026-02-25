// Convention: camelCase naming + try/catch error handling
export function handleError(error: Error) {
  try {
    console.error(error.message);
  } catch (e) {
    console.error("Failed to handle error");
  }
}
