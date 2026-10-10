(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.XB9Achievements=factory();})(typeof window!=='undefined'?window:globalThis,function(){
'use strict';
const defs=[
['first_sale','bronze','Первый хвост','Продай первую вещь в основной игре.',1],
['sample','bronze','Сначала образец','Подготовь первый образец XBOST.',1],
['supplier','bronze','Есть кому шить','Найди своё первое производство.',1],
['production','bronze','Не только на картинке','Выпусти первую партию товара.',1],
['decision','bronze','Вопрос закрыт','Прими решение по первому главному событию.',1],
['task','bronze','На связи','Получи выполненное поручение сотрудника.',1],
['live','bronze','Вышли из чата','Заверши первую LIVE-активность.',1],
['ability','bronze','Человек с особенностями','Используй уникальную способность агента.',1],
['dossier','bronze','Не кот в мешке','Изучи полное досье перед подключением сотрудника.',1],
['region','bronze','На карте отметились','Проведи региональную рекламную кампанию.',1],
['profit','bronze','Плюс существует','Заверши квартал с положительным денежным потоком.',1],
['sold25','bronze','Не только для своих','Продай 25 вещей за одно прохождение.',25],
['sold120','silver','Бабульки действительно оценили','Продай 120 вещей за одно прохождение.',120],
['aware25','silver','Слухами земля','Достигни узнаваемости 25.',25],
['team3','silver','Уже коллектив','Заручись поддержкой или найми трёх руководителей.',3],
['department','silver','Отделу тесно','Подключи первое платное расширение отдела.',1],
['synergy','silver','Сработались','Используй любую парную синергию.',1],
['live_types','silver','И словом, и встречей','Заверши интервью и мероприятие в одном прохождении.',2],
['profit3','silver','Это уже система','Заверши три квартала с положительным денежным потоком.',3],
['regional_profit','silver','Не только Коптево','Получи положительную оценку квартального вклада точки вне Коптево.',1],
['finish','gold','Держусь за хвост','Заверши все 20 кварталов без банкротства.',1],
['world','gold','Мировое госХвоство','Достигни пятого этапа, международности 10 и влияния 15 в зарубежном регионе.',1],
['banya','gold','Синдикат собран','Организуй БАННЫЙ СИНДИКАТ. Исход не важен.',1],
['no_debt','gold','Ничего не должны','Заверши 20 кварталов без банкротства и без долга.',1],
['platinum','platinum','Хвост всему голова','Собери все 24 основных достижения в любых прохождениях.',24]
].map(([id,tier,name,description,target])=>({id,tier,name,description,target}));
function progress(g){
 if(!g||g.training)return {};const m=g.v9metrics||{},q=g.quarterStats||[],team=Object.values(g.team||{}),regs=Object.values(g.map?.regions||{}),hist=g.liveHistory||[];
 const foreign=['berlin','istanbul','newyork','paris','tokyo','seoul','dubai','london','world','europe','asia','usa'];
 const p={first_sale:Math.min(1,g.soldTotal||0),sample:g.productReady?1:0,supplier:g.supplier?1:0,production:m.productions||0,decision:m.decisions||0,task:m.tasksCompleted||0,live:hist.length,ability:m.specials||0,dossier:m.dossiers||0,region:m.regionalPromos||0,profit:q.filter(x=>x.profit>0).length,sold25:g.soldTotal||0,sold120:g.soldTotal||0,aware25:g.awareness||0,team3:team.filter(x=>x.active).length,department:team.filter(x=>x.extension?.active).length,synergy:m.synergies||0,live_types:((m.interviews||0)>0?1:0)+((m.events||0)>0?1:0),profit3:q.filter(x=>x.profit>0).length,regional_profit:m.profitableRegionalBranch?1:0,finish:g.finished&&!g.bankrupt&&g.turn>=20?1:0,world:g.stage>=4&&g.international>=10&&foreign.some(id=>(g.map?.regions?.[id]?.influence||0)>=15)?1:0,banya:g.banya?.used||0,no_debt:g.finished&&!g.bankrupt&&g.turn>=20&&g.debt<=0?1:0};
 return p;
}
function merge(previous,g,now){const out=JSON.parse(JSON.stringify(previous||{})),p=progress(g),unlocked=[];for(const d of defs.filter(x=>x.id!=='platinum')){const a=out[d.id]||{progress:0,unlockedAt:null};a.progress=Math.max(a.progress||0,Math.min(d.target,Math.max(0,Number(p[d.id])||0)));if(!a.unlockedAt&&a.progress>=d.target){a.unlockedAt=now;unlocked.push(d.id);}out[d.id]=a;}const n=defs.filter(d=>d.id!=='platinum'&&out[d.id]?.unlockedAt).length;const a=out.platinum||{progress:0,unlockedAt:null};a.progress=n;if(n===24&&!a.unlockedAt){a.unlockedAt=now;unlocked.push('platinum');}out.platinum=a;return {records:out,unlocked};}
return {definitions:defs,progress,merge};
});
