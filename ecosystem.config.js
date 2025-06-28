module.exports = {
  /**
   * Application configuration section
   * http://pm2.keymetrics.io/docs/usage/application-declaration/
   */
  apps : [

    // First application
    {
      name      : 'bkm-bookmarks',
      script    : 'server.js',
      //watch: true,
      watch_delay: 1000,
      ignore_watch : ["node_modules", "logs", "temp", "tmp", "data"],
      watch_options: {
        "followSymlinks": false
      },
      env: {
        COMMON_VARIABLE: 'true'
      },
      env_production : {
        NODE_ENV: 'production'
      }
    }
  ]
};
