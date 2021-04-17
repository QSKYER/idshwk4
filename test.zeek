event zeek_init()
    {
    local a1 = SumStats::Reducer($stream="all_code_num", $apply=set(SumStats::UNIQUE));
    local a2 = SumStats::Reducer($stream="all_404_num", $apply=set(SumStats::UNIQUE));
    local a3 = SumStats::Reducer($stream="all_404_url_num", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="work",
                      $epoch=10min,
                      $reducers=set(a1,a2,a3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        	local b1 = result["all_code_num"];
                        	local b2 = result["all_404_num"];
	        	         	local b3 = result["all_404_url_num"];
	        	         	if (b2$num>2)
	        	            {
	        	             	if ((b2$num/b1$num)>0.2)
	        	             	{
	        	 	            	if((b3$unique/b2$num)>0.5)
	        		               	{
	        		            		print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, b2$num, b3$unique);
                                	}
	        	              	}
	        	             }
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    	SumStats::observe("all_code_num", [$host=c$id$orig_h], [$num=code]);
	if(code==404)
	{
		SumStats::observe("all_404_num", [$host=c$id$orig_h], [$num=code]);
		SumStats::observe("all_404_url_num", [$host=c$id$orig_h], [$str=c$http$uri]);
	}
    }

