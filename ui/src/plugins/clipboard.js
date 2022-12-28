export default {
  clipboard: navigator.clipboard,
  clipboardData: window.clipboardData,

  write(text) {
    console.log('copy', text);
    this.clipboard.writeText(text).then();
    this.clipboardData.setData('Text', text);
  },

  read() {
    console.log('clipboard', this.clipboard);
    if (this.clipboard) {
      return this.clipboard.readText();
    }

    console.log('clipboardData', this.clipboardData);
    if (this.clipboardData) {
      console.log(this.clipboardData?.getData('Text'));
      return new Promise((resolve) => {
        resolve(this.clipboardData?.getData('Text') || '')
      });
    }

    return new Promise(resolve => resolve(''));
  }
}
