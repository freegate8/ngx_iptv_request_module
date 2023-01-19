
/*
 * Copyright (C) liyin.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/md5.h>
#include <hiredis/hiredis.h>
#include <time.h>


typedef struct {
    ngx_str_t                 uri;
    ngx_array_t              *vars;
} ngx_iptv_request_conf_t;

typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_iptv_request_ctx_t;

typedef struct {
    ngx_int_t                 index;
    ngx_http_complex_value_t  value;
    ngx_http_set_variable_pt  set_handler;
} ngx_iptv_request_variable_t;


static ngx_int_t ngx_iptv_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_iptv_request_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static ngx_int_t ngx_iptv_request_set_variables(ngx_http_request_t *r,
    ngx_iptv_request_conf_t *arcf, ngx_iptv_request_ctx_t *ctx);
static ngx_int_t ngx_iptv_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_iptv_request_create_conf(ngx_conf_t *cf);
static char *ngx_iptv_request_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_iptv_request_init(ngx_conf_t *cf);
static char *ngx_iptv_request(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_iptv_request_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#ifdef HASS_HTTP_HEADER
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
#endif

void get_url_var(ngx_http_request_t *r, u_char * args, u_char* key, u_char* value, size_t len);

void hass_chk(const unsigned char* data, int len, u_char* md5sum);

ngx_int_t hass_verify(ngx_http_request_t *r, ngx_iptv_request_conf_t* arcf);

void get_auth_pwd();

static u_char g_live_sign[50] = {0};
static u_char g_live_auth_enable[1] = {'0'};

static ngx_command_t  ngx_iptv_request_commands[] = {

    { ngx_string("iptv_request"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_iptv_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("iptv_request_set"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_iptv_request_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_iptv_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_iptv_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_iptv_request_create_conf,     /* create location configuration */
    ngx_iptv_request_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_iptv_request_module = {
    NGX_MODULE_V1,
    &ngx_iptv_request_module_ctx,     /* module context */
    ngx_iptv_request_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_iptv_request_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t               *h, *ho;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_iptv_request_ctx_t   *ctx;
    ngx_iptv_request_conf_t  *arcf;

    arcf = ngx_http_get_module_loc_conf(r, ngx_iptv_request_module);

    if (arcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV] AUTH REQUEST HANDLER");

    ctx = ngx_http_get_module_ctx(r, ngx_iptv_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        
        if (ngx_iptv_request_set_variables(r, arcf, ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        if(hass_verify(r, arcf) == 0)
	    {
	        return NGX_OK;
	    }else{
	        return NGX_HTTP_FORBIDDEN;
	    }
	    
        /* return appropriate status */

        if (ctx->status == NGX_HTTP_FORBIDDEN) {
            return ctx->status;
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
            sr = ctx->subrequest;

            h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            if (h) {
                ho = ngx_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return NGX_ERROR;
                }

                *ho = *h;

                r->headers_out.www_authenticate = ho;
            }

            return ctx->status;
        }

        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[IPTV] auth request unexpected status: %d", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_iptv_request_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_iptv_request_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_iptv_request_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_iptv_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_iptv_request_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[IPTV] auth request done s:%d", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static ngx_int_t
ngx_iptv_request_set_variables(ngx_http_request_t *r,
    ngx_iptv_request_conf_t *arcf, ngx_iptv_request_ctx_t *ctx)
{
    ngx_str_t                          val;
    ngx_http_variable_t               *v;
    ngx_http_variable_value_t         *vv;
    ngx_iptv_request_variable_t  *av, *last;
    ngx_http_core_main_conf_t         *cmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[IPTV] AUTH REQUEST SET VARIABLES");

    if (arcf->vars == NULL) {
        return NGX_OK;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_iptv_request_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[IPTV] auth request variable");

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_iptv_request_create_conf(ngx_conf_t *cf)
{
    ngx_iptv_request_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_iptv_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_iptv_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_iptv_request_conf_t *prev = parent;
    ngx_iptv_request_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->uri, prev->uri, "");
    ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_iptv_request_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    get_auth_pwd();

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_iptv_request_handler;

    return NGX_OK;
}


static char *
ngx_iptv_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_iptv_request_conf_t *arcf = conf;

    ngx_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    arcf->uri = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_iptv_request_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_iptv_request_conf_t *arcf = conf;

    ngx_str_t                         *value;
    ngx_http_variable_t               *v;
    ngx_iptv_request_variable_t  *av;
    ngx_http_compile_complex_value_t   ccv;
    
    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "[IPTV] invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (arcf->vars == NGX_CONF_UNSET_PTR) {
        arcf->vars = ngx_array_create(cf->pool, 1,
                                      sizeof(ngx_iptv_request_variable_t));
        if (arcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    av = ngx_array_push(arcf->vars);
    if (av == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    av->index = ngx_http_get_variable_index(cf, &value[1]);
    if (av->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = ngx_iptv_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#ifdef HASS_HTTP_HEADER
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
        return &h[i];
    }

    /*
    No headers was found
    */
    return NULL;
}
#endif

void get_url_var(ngx_http_request_t *r, u_char * args, u_char * key, u_char* value, size_t len)
{
    if(args == NULL) return;
        
    u_char * offset = ngx_strcasestrn(args, (char *)key, ngx_strlen(key)-1);

    if(offset != NULL)
    {
        offset += ngx_strlen(key);
        u_char * end = ngx_strcasestrn(offset, "&", 0);
        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,   "[IPTV] ===end:%p", end);

        if(end == NULL)
        {   
            end = ngx_strcasestrn(offset, " ", 0);    
            //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,   "[IPTV] ===end2:%p", end); 
            if(end == NULL)
            {   
                end = ngx_strcasestrn(offset, "\n", 0);    
                //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,   "[IPTV] ===end3:%p", end); 
            }       
        }
        if(end != NULL)
        {
            ngx_cpystrn(value, offset, end-offset+1);
            //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,   "[IPTV] ===value:%s", value);
        }   
    }
    
}

void hass_chk(const unsigned char* data, int len, u_char* md5sum)
{
    unsigned char md[16];
    MD5((unsigned char*) data, len,  md);
	char  tmp[3]={ '\0' };
	for  (int i = 0; i < 16; i++){
		sprintf (tmp, "%2.2x" ,md[i]);
		strcat ((char*)md5sum,tmp);
	}   
    
}

ngx_int_t hass_verify(ngx_http_request_t *r, ngx_iptv_request_conf_t* arcf)
{
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[IPTV] HASS VERIFY: \"%V?%V\", uri:%s",
                       &r->uri, &r->args, arcf->uri.data);
    
    if(strcasestr((const char*)r->uri.data, (const char*)arcf->uri.data) == NULL)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV] REQUEST NOT IN MOD [%s],[%s]", r->uri.data, arcf->uri.data);
        return NGX_OK;
    }
    
    // live_auth_enable 开关
    if(memcmp(g_live_auth_enable, "0", 1) == 0)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV] g_live_auth_enable:[%s]", g_live_auth_enable);
        return NGX_OK;
    }
    
    if(r->args.data == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV] url args invalid!");
        return NGX_ERROR;
    }
    
    //get_auth_pwd() 
    u_char sign[33]= {0};
    get_url_var( r, r->args.data, (u_char *)"sign=", sign, 33);
    if(ngx_strlen(g_live_sign) != 0 && ngx_strncmp(sign, g_live_sign, ngx_strlen(sign))==0)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV] SAME AS live_sign! SO PASS:[%s]", g_live_sign);
        return NGX_OK;
    }
    
    u_char time[33]= {0};
    get_url_var( r, r->args.data, (u_char *)"time=", time, 33);
    
    u_char ttl[33] = {0};
    get_url_var( r, r->args.data, (u_char *)"ttl=", ttl, 33);
    
    u_char client[100]= {0};
    get_url_var( r, r->args.data, (u_char *)"client=", client, 100);
    
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]time:[%s], ttl:[%s], client:[%s], sign:[%s]", time, ttl, client, sign);
    
    time_t ttl_t = atol((const char *)ttl);
    if(ttl_t == 0) //未传入ttl
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]No TTL args supply!");
        return NGX_ERROR;
    }
    if(ttl_t> 60*60*24) //ttl的值过大
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]Too Large TTL VALUE!");
        return NGX_ERROR;
    }
    
    time_t now = ngx_time();
    time_t start_t = atol((const char *)time);
    if(abs(start_t-now) > 600) //客户端和当前系统时间差值过大
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]CLIENT AND SERVER TIME DIFF OUTRANGE!===========now:[%ll], time:[%ll]", now, start_t);
        return NGX_ERROR;
    }
    
    time_t end_time = start_t + ttl_t;
    if(now > end_time)  //过期
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]EXPIRED!===========now:[%ll], endtime:[%ll]", now, end_time);
        return NGX_ERROR;
    }
    
    char buff[1024]= {0};
    strcat(buff, (const char*)time);
    strcat(buff, (const char*)ttl);
    strcat(buff, (const char*)client);
    strcat(buff, "hsmediaCluster");
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]CAT=[%s]",buff);
    
    u_char md5sum[33] = {0};
    hass_chk((const unsigned char*) buff, strlen(buff), md5sum);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]MD5=[%s]",md5sum);

    ngx_int_t same = ngx_strcasecmp(md5sum, sign);
    if(same == 0) return NGX_OK;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[IPTV]NO SAME!==========MD5=[%s], SIGN=[%s]",md5sum, sign);
    return NGX_ERROR;
}

void get_auth_pwd()
{
    redisContext* _connect = NULL;
    redisReply* _reply = NULL;
    _connect = redisConnect("127.0.0.1", 6379);
    if(_connect == NULL || ( _connect != NULL && _connect->err))
    {
        return;
    }
    
    _reply = (redisReply*)redisCommand(_connect, "GET %s", "live_sign");
    if(_reply->str != NULL)
    {
        strncpy((char*)g_live_sign, (char*) _reply->str, 50);
        freeReplyObject(_reply);
    }    
    _reply = (redisReply*)redisCommand(_connect, "GET %s", "live_auth_enable");
    if(_reply->str != NULL)
    {
        strncpy((char*)g_live_auth_enable, (char*) _reply->str, 1);
        freeReplyObject(_reply);
    }
    
    redisFree(_connect);
    
}